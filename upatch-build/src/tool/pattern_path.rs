use std::ffi::{OsStr, OsString};
use std::os::unix::prelude::OsStrExt;
use std::path::{Component, Path, PathBuf};

use super::{file_name, list_all_dirs, list_all_files};

pub fn glob<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<PathBuf>> {
    let components = Path::new(path.as_ref()).components().collect::<Vec<_>>();
    let mut pathes = vec![PathBuf::new()];

    if components[0].ne(&Component::RootDir)
        && components[0].ne(&Component::CurDir)
        && components[0].ne(&Component::ParentDir)
    {
        push_path(Component::CurDir, &mut pathes);
    }

    for i in 0..components.len() {
        match components[i] {
            Component::RootDir | Component::CurDir | Component::ParentDir => {
                push_path(components[i], &mut pathes);
            }
            _ => {
                let mut path_clone = vec![];
                for p in &mut pathes {
                    let tmp = p.join(components[i]);
                    match tmp.exists() {
                        true => path_clone.push(tmp),
                        false => {
                            let all_pathes = match i == (components.len() - 1) {
                                true => list_all_files(&p, false),
                                false => list_all_dirs(&p, false),
                            }?;
                            for name in find_name(components[i].as_os_str(), all_pathes)? {
                                path_clone.push(p.join(name));
                            }
                        }
                    };
                }
                pathes = path_clone;
            }
        };
    }
    Ok(pathes)
}

fn push_path<O: AsRef<OsStr>>(name: O, pathes: &mut Vec<PathBuf>) {
    for p in pathes {
        *p = p.join(name.as_ref());
    }
}

fn find_name(name: &OsStr, all_pathes: Vec<PathBuf>) -> std::io::Result<Vec<OsString>> {
    let mut result = Vec::new();
    for dir in all_pathes {
        let path_name = file_name(dir)?;
        if pattern_match(path_name.as_bytes(), name.as_bytes()) {
            result.push(path_name);
        }
    }
    Ok(result)
}

fn pattern_match(name: &[u8], pattern: &[u8]) -> bool {
    let (mut i, mut j) = (0, 0);
    let (mut i_star, mut j_star) = (-1, -1);
    let (m, n) = (name.len(), pattern.len());

    while i < m {
        if j < n && (name[i].eq(&pattern[j]) || pattern[j].eq(&63)) {
            i += 1;
            j += 1;
        } else if j < n && pattern[j].eq(&42) {
            i_star = i as i32;
            j_star = j as i32;
            j += 1;
        } else if i_star >= 0 {
            i_star += 1;
            i = i_star as usize;
            j = (j_star + 1) as usize;
        } else {
            return false;
        }
    }
    while j < n && pattern[j].eq(&42) {
        j += 1;
    }
    j == n
}
