use std::{
    borrow::Cow,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use zip::ZipArchive;

use crate::fvdl_reader::Fvdl;

mod fvdl_reader;

fn main() -> anyhow::Result<()> {
    let path = Path::new("test.fpr");

    let fpr = File::open(path)?;

    println!("Fpr len: {}", fpr.metadata()?.len());

    let mut zipfile = ZipArchive::new(fpr)?;

    let filenames = zipfile.file_names().collect::<Vec<_>>();

    let mut version = String::new();
    BufReader::new(zipfile.by_name("VERSION")?).read_line(&mut version)?;
    let version = version.trim_end();
    println!("Fpr version: {:?}", version.trim_end());

    let fvdl = zipfile.by_name("audit.fvdl")?;
    let scan: Fvdl = quick_xml::de::from_reader(BufReader::new(fvdl))?;
    dbg!(scan);

    Ok(())
}
