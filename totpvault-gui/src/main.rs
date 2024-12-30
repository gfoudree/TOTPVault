mod dev;
use totpvault_lib::*;

use gtk::prelude::{BoxExt, ButtonExt, GtkWindowExt, OrientableExt};
use relm4::{gtk::{self, gdk::Display, gio, prelude::{Cast, FrameExt, WidgetExt}, CssProvider, StyleContext}, ComponentParts, ComponentSender, RelmApp, RelmWidgetExt, SimpleComponent};
use relm4::gtk::prelude::GridExt;
use log::{info, warn, error};
use env_logger::Builder;
use std::env;

struct AppModel {
    counter: u8,
    device_online: bool,
}

#[derive(Debug)]
enum AppMsg {
    DeviceEvent
}
struct AppWidgets {
    status_label: gtk::Label,
    path_label: gtk::Label,
    slot_usage_label: gtk::Label,
    time_sync_label: gtk::Label,
    hw_version_label: gtk::Label,
    sw_version_label: gtk::Label,
    public_key_label: gtk::Label,
    notebook: gtk::Notebook,
}

impl SimpleComponent for AppModel {
    type Init = u8;

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
        let mut model = AppModel{counter, device_online: false};

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
        let frame = gtk::Frame::builder().margin_top(5).margin_bottom(5).margin_end(5).build();
        let info_grid = gtk::Grid::builder().margin_bottom(20).margin_start(15).valign(gtk::Align::End).vexpand(true).build();
        let status_label = gtk::Label::builder().label("Status:").halign(gtk::Align::Start).margin_bottom(10).build();
        let path_label = gtk::Label::builder().label("Path:").halign(gtk::Align::Start).margin_bottom(10).build();
        let slot_usage_label = gtk::Label::builder().label("Slot Usage:").halign(gtk::Align::Start).margin_bottom(10).build();
        let time_sync_label = gtk::Label::builder().label("Time Sync:").halign(gtk::Align::Start).margin_bottom(10).build();
        let hw_version_label = gtk::Label::builder().label("HW Version:").halign(gtk::Align::Start).margin_bottom(10).build();
        let sw_version_label = gtk::Label::builder().label("SW Version:").halign(gtk::Align::Start).margin_bottom(10).build();
        let public_key_label = gtk::Label::builder().label("Public Key:").halign(gtk::Align::Start).margin_bottom(10).build();

        info_grid.attach(&status_label, 0, 0, 1, 1);
        info_grid.attach(&path_label, 0, 1, 1, 1);
        info_grid.attach(&slot_usage_label, 0, 2, 1, 1);
        info_grid.attach(&time_sync_label, 0, 3, 1, 1);
        info_grid.attach(&hw_version_label, 0, 4, 1, 1);
        info_grid.attach(&sw_version_label, 0, 5, 1, 1);
        info_grid.attach(&public_key_label, 0, 6, 1, 1);

        info_box.append(&info_grid);

        frame.set_child(Some(&info_box));
        top_layout.append(&frame);

        // Main tab page
        let main_page = gtk::Box::builder().spacing(5).halign(gtk::Align::Fill).valign(gtk::Align::Fill).orientation(gtk::Orientation::Vertical).build();
        let totp_scrolled_window = gtk::ScrolledWindow::builder().halign(gtk::Align::Fill).hexpand(true).vexpand(true).build();
        let totp_list_box = gtk::ListBox::builder().selection_mode(gtk::SelectionMode::None).build();
        let time_progressbar = gtk::ProgressBar::builder().text("30s").show_text(true).build();
        totp_scrolled_window.set_child(Some(&totp_list_box));
        main_page.append(&totp_scrolled_window);
        main_page.append(&time_progressbar);
        
        // Populate elements
        for _ in 0..25 {
            let row = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).margin_start(20).margin_end(20).margin_top(8).margin_bottom(8).spacing(24).build();
            let domain_lbl = gtk::Label::builder().label("Google.com").halign(gtk::Align::Start).valign(gtk::Align::Center).build();
            let totp_lbl = gtk::Label::builder().label("042143").halign(gtk::Align::Start).valign(gtk::Align::Center).build();
            let copy_img = gtk::Image::builder().resource("/com/example/ui/icons/clipboard-symbolic.svg").pixel_size(16).build();
            row.append(&domain_lbl);
            row.append(&totp_lbl);
            row.append(&copy_img);
            totp_list_box.append(&row);
        }

        // Create Configure page
        let create_totp_entry_page = gtk::Box::builder().spacing(5).halign(gtk::Align::Center).valign(gtk::Align::Center).orientation(gtk::Orientation::Vertical).build();
        let sync_time_button = gtk::Button::builder().label("Sync Time").build();
        let attest_challenge_button = gtk::Button::builder().label("Attest Key").build();
        let delete_selection_combobox = gtk::ComboBoxText::new();
        delete_selection_combobox.append_text("google.com");
        create_totp_entry_page.append(&delete_selection_combobox);
    
        create_totp_entry_page.append(&sync_time_button);
        create_totp_entry_page.append(&attest_challenge_button);

        // Build notebook with all the tabs
        notebook.append_page(&main_page, Some(&gtk::Label::new(Some("TOTP Codes"))));
        notebook.append_page(&create_totp_entry_page, Some(&gtk::Label::new(Some("Configure"))));

        root.set_child(Some(&top_layout));

        
        // Display if any devices are plugged in
        match dev::TotpvaultDev::find_device() {
            Ok(dev) => {
                info!("Using device {}", dev);

                // Check if device is locked or unlocked
                let status_msg = dev::TotpvaultDev::get_device_status(dev.as_str());
                println!("Status: {:?}", status_msg);
                path_label.set_text(format!("Device:\t\t\t {}", dev).as_str());
                status_label.set_text("Status:\t\t\t Device Inserted");
                model.device_online = true;
            }
            Err(e) => {
                status_label.set_text("Status:\t No device inserted. Please restart");
                warn!("{}", e);
            }
        }
        
        let widgets = AppWidgets {
            status_label,
            path_label,
            slot_usage_label,
            time_sync_label,
            hw_version_label,
            sw_version_label,
            public_key_label,
            notebook,
        };

        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, _sender: ComponentSender<Self>) {
        match msg {
            AppMsg::DeviceEvent => {

            }
        }
    }

    fn update_view(&self, widgets: &mut Self::Widgets, _sender: ComponentSender<Self>) {
        
    }
}

fn main() {
    Builder::new()
    .parse_filters("info")  // Set to 'info' to show info and above levels
    .init();

    gio::resources_register_include!("icons.gresource").unwrap();
    let app = RelmApp::new("relm4.test.simple");

    app.run::<AppModel>(0);
}