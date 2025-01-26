mod dev;

use gtk::prelude::{BoxExt, GtkWindowExt};
use relm4::{gtk::{self, gdk::Display, gio, prelude::{FrameExt}, CssProvider, StyleContext}, ComponentParts, ComponentSender, RelmApp, SimpleComponent};
use relm4::gtk::prelude::{ButtonExt, GridExt, WidgetExt};
use log::{info, warn, error, debug};
use env_logger::Builder;
use std::{env, thread};
use std::time::Duration;
use base64::prelude::BASE64_STANDARD;
use chrono::Utc;
use base64::prelude::*;
use sha2::{Digest, Sha256};
use hex;
use relm4::gtk::glib::clone;

const TOTP_TICK_SECONDS: f64 = 30.0;
const ALLOWED_TIMESYNC_DELTA: i64 = 10;

struct AppModel {
    counter: f64,
    device_online: bool,
    device_path: String,
    device_time_in_sync: bool,
    device_unlocked: bool,
    device_used_slots: u8,
    device_available_slots: u8,
}

#[derive(Debug)]
enum AppMsg {
    TimerTick,
    SyncTime,
}
struct AppWidgets {
    status_label: gtk::Label,
    path_label: gtk::Label,
    slot_usage_label: gtk::Label,
    time_sync_label: gtk::Label,
    version_label: gtk::Label,
    public_key_label: gtk::Label,
    notebook: gtk::Notebook,
    time_progressbar: gtk::ProgressBar,
    totp_list_box: gtk::ListBox,
    attest_challenge_button: gtk::Button,
    add_entry_submit_button: gtk::Button,
    sync_time_button: gtk::Button,
    delete_entry_button: gtk::Button,
}

fn get_remaining_totp_ticks() -> f64 {
    let ts = Utc::now();
    return (30 - (ts.timestamp() % 30)) as f64;
}

fn timesync_check(device_timestamp: u64) -> bool {
    let current_time = Utc::now().timestamp() as u64;
    let time_delta = ((current_time - device_timestamp) as i64).abs();

    info!("System time (UTC): {}     Device time (UTC): {}     Delta: {}", current_time, device_timestamp, time_delta);
    if time_delta > ALLOWED_TIMESYNC_DELTA {
        return false
    }
    return true
}

fn public_key_to_hash(b64_publickey: &str) -> Result<String, String> {
    let decoded = BASE64_STANDARD.decode(b64_publickey).map_err(|e| e.to_string())?;
    let digest = Sha256::digest(decoded);

    let hash_str = hex::encode(digest);
    let mut formatted = String::from("");
    for chunk in hash_str.chars().collect::<Vec<char>>().chunks(2) {
        formatted += format!("{}{}:", chunk[0], chunk[1]).as_str();
    }
    if formatted.chars().last().unwrap() == ':' {
        formatted = formatted[..formatted.len()-1].to_string();
    }
    formatted = formatted.to_uppercase();
    return Ok(formatted);

}

fn populate_ui(dev: &str, model: &mut AppModel, widgets: &AppWidgets) -> bool{
    // Check if device is locked or unlocked
    match dev::TotpvaultDev::get_device_status(dev) {
        Ok(status_msg) => {
            // Populate metadata about device
            let hsh_truncated = &public_key_to_hash(status_msg.public_key.as_str()).unwrap()[0..23]; // Truncate hash, full hash to terminal out
            widgets.public_key_label.set_text(format!("Public Key:\t\t {}", hsh_truncated).as_str()); // Necessary to trim extra null bytes for some reason
            widgets.version_label.set_text(format!("Version:\t\t{}", status_msg.version_str).as_str());

            model.device_time_in_sync = timesync_check(status_msg.current_timestamp);
            model.device_unlocked = status_msg.vault_unlocked;
            model.device_used_slots = status_msg.used_slots;
            model.device_available_slots = status_msg.total_slots;

            // Log out to terminal
            info!("Device fingerprint (SHA256): {}", public_key_to_hash(status_msg.public_key.as_str()).unwrap());
            debug!("Device Status: {:?}", status_msg);
        }
        Err(e) => {
            widgets.status_label.set_text("Status:\t No device inserted. Please restart");
            error!("Error getting status from device: {}", e);
            return false;
        }
    }

    // Get list of stored entries on device
    match dev::TotpvaultDev::list_stored_credentials(dev) {
        Ok(credentials) => {
            for credential in credentials {
                // Get TOTP code
                match dev::TotpvaultDev::get_totp_code(&credential) {
                    Ok(totp_code) => {
                        // Populate elements
                        let row = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).margin_start(20).margin_end(20).margin_top(8).margin_bottom(8).spacing(24).build();
                        let domain_lbl = gtk::Label::builder().label(credential.domain_name).halign(gtk::Align::Start).valign(gtk::Align::Center).build();
                        let totp_lbl = gtk::Label::builder().label(totp_code).halign(gtk::Align::Start).valign(gtk::Align::Center).build();
                        let copy_img = gtk::Image::builder().resource("/com/example/ui/icons/clipboard-symbolic.svg").pixel_size(16).build();
                        row.append(&domain_lbl);
                        row.append(&totp_lbl);
                        row.append(&copy_img);
                        widgets.totp_list_box.append(&row);
                    }
                    Err(e) => {
                        error!("Error getting TOTP code for credential {:?} : {}", credential, e);
                    }
                }
            }
        }
        Err(e) => {
            error!("Error listing credentials on device {}: {}", dev, e);
            return false;
        }
    }
    return true;
}

fn toggle_disable_widgets(disable: bool, widgets: &AppWidgets) {
    widgets.sync_time_button.set_sensitive(disable);
    widgets.attest_challenge_button.set_sensitive(disable);
    widgets.add_entry_submit_button.set_sensitive(disable);
    widgets.delete_entry_button.set_sensitive(disable);
}

impl SimpleComponent for AppModel {
    type Init = f64;
    type Input = AppMsg;
    type Output = ();
    type Root = gtk::Window;
    type Widgets = AppWidgets;

    fn init_root() -> Self::Root {
        gtk::Window::builder().title("TOTP").default_height(700).default_width(1100).build()
    }

    // Initialize the UI.
    fn init(
        counter: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let mut model = AppModel{counter, device_online: false, device_path: "".to_string(), device_time_in_sync: false, device_unlocked: false, device_used_slots: 0, device_available_slots: 0 };

        let provider = CssProvider::new();
        provider.load_from_data(String::from_utf8(include_bytes!("style.css").to_vec()).unwrap().as_str());
        let display = Display::default().unwrap();
        StyleContext::add_provider_for_display(&display, &provider, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);


        let notebook = gtk::Notebook::builder().hexpand(true).vexpand(true).build();
        let top_layout = gtk::Box::builder().spacing(0).orientation(gtk::Orientation::Horizontal).build();

        let notebook_box = gtk::Box::builder().spacing(5).orientation(gtk::Orientation::Vertical).hexpand(true).vexpand(true).margin_top(5).margin_bottom(5).margin_end(5).margin_start(5).build(); // Have the box expand to take the remaining space
        notebook_box.append(&notebook);
        let info_box = gtk::Box::builder().spacing(5).orientation(gtk::Orientation::Vertical).width_request(300).vexpand(true).build();

        top_layout.append(&notebook_box);

        // Create info side panel
        let info_panel_frame = gtk::Frame::builder().margin_top(5).margin_bottom(5).margin_end(5).build();
        let info_grid = gtk::Grid::builder().margin_bottom(20).margin_start(15).valign(gtk::Align::End).vexpand(true).build();
        let status_label = gtk::Label::builder().label("Status:").halign(gtk::Align::Start).margin_bottom(10).build();
        let path_label = gtk::Label::builder().label("Path:").halign(gtk::Align::Start).margin_bottom(10).build();
        let slot_usage_label = gtk::Label::builder().label("Slot Usage:").halign(gtk::Align::Start).margin_bottom(10).build();
        let time_sync_label = gtk::Label::builder().label("Time Sync:").halign(gtk::Align::Start).margin_bottom(10).build();
        let version_label = gtk::Label::builder().label("Version:").halign(gtk::Align::Start).margin_bottom(10).build();
        let public_key_label = gtk::Label::builder().label("Public Key:").halign(gtk::Align::Start).margin_bottom(10).build();

        info_grid.attach(&status_label, 0, 0, 1, 1);
        info_grid.attach(&path_label, 0, 1, 1, 1);
        info_grid.attach(&slot_usage_label, 0, 2, 1, 1);
        info_grid.attach(&time_sync_label, 0, 3, 1, 1);
        info_grid.attach(&version_label, 0, 4, 1, 1);
        info_grid.attach(&public_key_label, 0, 5, 1, 1);

        info_box.append(&info_grid);

        info_panel_frame.set_child(Some(&info_box));
        top_layout.append(&info_panel_frame);

        // Main tab page
        let main_page = gtk::Box::builder().spacing(5).halign(gtk::Align::Fill).valign(gtk::Align::Fill).orientation(gtk::Orientation::Vertical).build();
        let totp_scrolled_window = gtk::ScrolledWindow::builder().halign(gtk::Align::Fill).hexpand(true).vexpand(true).build();
        let totp_list_box = gtk::ListBox::builder().selection_mode(gtk::SelectionMode::None).build();

        let remaining_totp_ticks = get_remaining_totp_ticks();
        model.counter = remaining_totp_ticks*(1.0/TOTP_TICK_SECONDS);
        let time_progressbar = gtk::ProgressBar::builder().text(format!("{}s", remaining_totp_ticks as i32)).show_text(true).fraction(model.counter).build();
        totp_scrolled_window.set_child(Some(&totp_list_box));
        main_page.append(&totp_scrolled_window);
        main_page.append(&time_progressbar);

        // Create Configure page
        let create_totp_entry_page = gtk::Box::builder().spacing(5).halign(gtk::Align::Center).valign(gtk::Align::Center).orientation(gtk::Orientation::Vertical).build();
        let configure_grid = gtk::Grid::builder().margin_bottom(20).margin_start(15).valign(gtk::Align::End).vexpand(true).column_spacing(20).row_spacing(10).build();

        let add_entry_input_domain_name = gtk::Entry::builder().has_tooltip(true).tooltip_text("Domain name of website to store code for").build();
        let add_entry_input_totp_secret = gtk::Entry::builder().has_tooltip(true).tooltip_text("TOTP secret, base64 encoded").build();
        let add_entry_submit_button = gtk::Button::builder().label("Add").build();
        let sync_time_button = gtk::Button::builder().label("Sync Time").build();
        sync_time_button.connect_clicked(clone!(
            #[strong]
            sender,
            move |_| {
                sender.input(AppMsg::SyncTime);
            }
        ));

        let attest_challenge_button = gtk::Button::builder().label("Attest Key").has_tooltip(true).tooltip_text("Send challenge to key and authenticate it").build();
        let delete_selection_combobox = gtk::ComboBoxText::builder().has_tooltip(true).tooltip_text("Existing entry to delete").build();
        let delete_entry_button = gtk::Button::builder().label("Delete").build();
        delete_selection_combobox.append_text("google.com");

        configure_grid.attach(&gtk::Label::new(Some("Website")),0, 0, 1, 1);
        configure_grid.attach(&add_entry_input_domain_name,1, 0, 1, 1);
        configure_grid.attach(&gtk::Label::new(Some("TOTP Secret")),0, 1, 1, 1);
        configure_grid.attach(&add_entry_input_totp_secret,1, 1, 1, 1);
        create_totp_entry_page.append(&configure_grid);

        create_totp_entry_page.append(&add_entry_submit_button);
        create_totp_entry_page.append(&gtk::Separator::builder().orientation(gtk::Orientation::Horizontal).margin_bottom(30).margin_top(30).build());
        create_totp_entry_page.append(&delete_selection_combobox);
        create_totp_entry_page.append(&delete_entry_button);
        create_totp_entry_page.append(&gtk::Separator::builder().orientation(gtk::Orientation::Horizontal).margin_bottom(30).margin_top(30).build());
        create_totp_entry_page.append(&sync_time_button);
        create_totp_entry_page.append(&attest_challenge_button);

        // Build notebook with all the tabs
        notebook.append_page(&main_page, Some(&gtk::Label::new(Some("TOTP Codes"))));
        notebook.append_page(&create_totp_entry_page, Some(&gtk::Label::new(Some("Configure Key"))));

        root.set_child(Some(&top_layout));

        let widgets = AppWidgets {
            status_label,
            path_label,
            slot_usage_label,
            time_sync_label,
            version_label,
            public_key_label,
            notebook,
            time_progressbar,
            totp_list_box,
            attest_challenge_button,
            add_entry_submit_button,
            sync_time_button,
            delete_entry_button
        };

        // Display if any devices are plugged in
        match dev::TotpvaultDev::find_device() {
            Ok(dev) => {
                model.device_online = populate_ui(dev.as_str(), &mut model, &widgets);
                model.device_path = dev;
            }
            Err(e) => {
                widgets.status_label.set_text("Status:\t No device inserted. Please restart");
                warn!("{}", e);
            }
        }

        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_millis(1000));
                sender.input(AppMsg::TimerTick);
            }
        });
        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, _sender: ComponentSender<Self>) {
        match msg {
            AppMsg::TimerTick => {
                let time_value = 1.0/TOTP_TICK_SECONDS;
                if self.counter - time_value < 0.0 {
                    self.counter = 1.0;
                }
                else {
                    self.counter -= time_value;
                }
            },
            AppMsg::SyncTime => {
                if self.device_path != "" && self.device_online {
                    match dev::TotpvaultDev::sync_time(self.device_path.as_str()) {
                        Ok(_) => {
                            // Re-poll for the time and update the GUI if it is in sync now
                            if let Ok(dev_status) = dev::TotpvaultDev::get_device_status(self.device_path.as_str()) {
                                self.device_time_in_sync = timesync_check(dev_status.current_timestamp);
                            }
                        }
                        Err(e) => error!("Error syncing time with device! {}", e)
                    }
                } else {
                    debug!("Not syncing time, device is not online or the device path is empty");
                }
            }
        }
    }

    fn update_view(&self, widgets: &mut Self::Widgets, _sender: ComponentSender<Self>) {
        widgets.time_progressbar.set_fraction(self.counter);
        widgets.time_progressbar.set_text(Some(format!("{}s", (self.counter * TOTP_TICK_SECONDS) as i32).as_str()));

        match self.device_time_in_sync {
            true => widgets.time_sync_label.set_text("Time Sync:\t\t True"),
            false => widgets.time_sync_label.set_text("Time Sync:\t\t False"),
        }

        match self.device_unlocked {
            true => {
                widgets.status_label.set_text("Status:\t\t\t Online, UNLOCKED");

                // Enable Widgets
                toggle_disable_widgets(true, &widgets);
            },
            false => {
                widgets.status_label.set_text("Status:\t\t\t Online, LOCKED");

                // Disable Widgets
                toggle_disable_widgets(false, &widgets);
            }
        }

        widgets.path_label.set_text(format!("Path:\t\t\t {}", self.device_path).as_str());
        widgets.slot_usage_label.set_text(format!("Slot Usage:\t\t\t{} / {}", self.device_used_slots, self.device_available_slots).as_str());
    }
}

fn main() {
    Builder::new()
    .parse_filters("info")  // Set to 'info' to show info and above levels
    .init();

    gio::resources_register_include!("icons.gresource").unwrap();
    let app = RelmApp::new("relm4.test.simple");

    app.run::<AppModel>(1.0);
}