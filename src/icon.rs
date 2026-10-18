//! Menu bar icon: a ring with a pie wedge showing how full the disk is.
//! Drawn in code as a template image so it adapts to light/dark menu bars.

use tray_icon::Icon;

pub fn disk_pie(used_fraction: f64) -> Icon {
    const S: usize = 44; // 22pt @2x
    const SS: usize = 4; // supersampling for smooth edges
    let c = S as f64 / 2.0;
    let sweep = used_fraction.clamp(0.0, 1.0) * std::f64::consts::TAU;
    let mut rgba = vec![0u8; S * S * 4];
    for y in 0..S {
        for x in 0..S {
            let mut hits = 0;
            for sy in 0..SS {
                for sx in 0..SS {
                    let dx = x as f64 + (sx as f64 + 0.5) / SS as f64 - c;
                    let dy = y as f64 + (sy as f64 + 0.5) / SS as f64 - c;
                    let r = (dx * dx + dy * dy).sqrt();
                    // Angle clockwise from 12 o'clock.
                    let a = dx.atan2(-dy).rem_euclid(std::f64::consts::TAU);
                    let ring = (17.0..=20.0).contains(&r);
                    let wedge = r <= 14.0 && a <= sweep;
                    if ring || wedge {
                        hits += 1;
                    }
                }
            }
            rgba[(y * S + x) * 4 + 3] = (hits * 255 / (SS * SS)) as u8;
        }
    }
    Icon::from_rgba(rgba, S as u32, S as u32).expect("valid icon")
}
