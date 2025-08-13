// SPDX-License-Identifier: Apache-2.0
use std::ffi::CStr;
use std::os::unix::fs::DirEntryExt;
use std::path::{Path, PathBuf};
use std::{collections::HashMap, fs, process};

use anyhow::{anyhow, Context, Result};
use libbpf_rs::{libbpf_sys, skel::Skel, MapCore, MapType};

use super::{BPFState, MapState, PinState};

/// Collects a byte-vector copy of each key/value pair of data in the map
fn read_map(map: &libbpf_rs::Map) -> Result<HashMap<Vec<u8>, Vec<Vec<u8>>>> {
    let mut data = HashMap::new();
    if map.map_type().is_percpu() {
        for key in map.keys() {
            let val = map.lookup_percpu(key.as_slice(), libbpf_rs::MapFlags::ANY);
            data.insert(key, val?.context("Map value empty")?);
        }
    } else {
        for key in map.keys() {
            let val = map.lookup(key.as_slice(), libbpf_rs::MapFlags::ANY);
            data.insert(key, vec![val?.context("Map value empty")?]);
        }
    }
    Ok(data)
}

/// Transforms the [MapType] from Rust into the C string representation
/// from libbpf in order to match the output from bpftool
fn map_type_to_libbpf_str(map_type: MapType) -> Result<String> {
    // this unsafe code is required because returning a string from a C library
    // is inherently unsafe and uses memory not owned by the Rust program
    let c_str = unsafe {
        let raw_str = libbpf_sys::libbpf_bpf_map_type_str(map_type.into()) as *const u8;
        CStr::from_ptr(raw_str)
    };
    Ok(c_str.to_str()?.to_string())
}

/// Creates a HashMap of [MapState] from each map in a given skeleton
fn rust_maps(skel: &dyn Skel, ground_truth: &BPFState) -> Result<HashMap<String, MapState>> {
    let mut map_states = HashMap::new();
    for map in skel.object().maps() {
        let info = map.info()?;
        let name = info.name()?.to_string();
        let gt_map_state = match ground_truth.maps.get(&name) {
            Some(map_state) => map_state,
            None => return Err(anyhow!("\"{}\" map not found in ground truth", name)),
        };
        // don't read data if the map isn't static, it won't be tested
        let data = if gt_map_state.is_static {
            read_map(&map)?
        } else {
            Default::default()
        };
        map_states.insert(
            name,
            MapState {
                id: info.info.id,
                _type: map_type_to_libbpf_str(map.map_type())?,
                is_static: gt_map_state.is_static,
                bytes_key: info.info.key_size,
                bytes_value: info.info.value_size,
                data,
            },
        );
    }
    Ok(map_states)
}

/// Creates a [PinState] from the paths used in a BPF userspace
fn rust_pins(pin_dir: &PathBuf) -> Result<PinState> {
    if !Path::new(pin_dir).exists() {
        return Err(anyhow!(
            "pin directory {} not found",
            pin_dir.to_string_lossy()
        ));
    }
    let mut pins = HashMap::new();
    for entry in fs::read_dir(pin_dir)? {
        let entry = entry?;
        pins.insert(entry.file_name().to_string_lossy().to_string(), entry.ino());
    }
    Ok(PinState {
        dir: pin_dir.to_string_lossy().to_string(),
        pins,
    })
}

/// Creates a [BPFState] object from the perspective of the BPF
/// file-descriptors created and maintained by the Rust userspace
pub fn rust_state(skel: &dyn Skel, pin_dir: &PathBuf, ground_truth: &BPFState) -> Result<BPFState> {
    Ok(BPFState {
        pid: process::id(),
        maps: rust_maps(skel, ground_truth)?,
        pins: rust_pins(pin_dir)?,
    })
}
