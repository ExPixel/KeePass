use keepass::database;
use keepass::kdbx;
use keepass::security::ProtectedString;

pub fn main() {
    println!("sizeof: {} bytes", std::mem::size_of::<database::PwDatabase>());

    let mut database = Box::new(database::PwDatabase::new());
    let mut kdbx = Box::new(kdbx::Kdbx::new());

    database.add_user_key(database::UserKey::Password(database::KcpPassword::new("test", false)));
    keepass::kdbx::load_kdbx_file("data/database.kdbx", keepass::kdbx::KdbxFormat::Default, &mut database, &mut kdbx).unwrap();

    println!("> {} ({} entries)", database.root_group.borrow().name, database.root_group.borrow().entries.len());
    print_entries(&database.root_group, 1);
    print_groups(&database.root_group, 1);
}

fn print_groups(group: &database::WrappedPwGroup, depth: u32) {
    for subgroup in group.borrow().groups.iter() {
        println!("{}> {} ({} entries)", depth_str(depth), subgroup.borrow().name, subgroup.borrow().entries.len());
        print_entries(subgroup, depth);
        print_groups(subgroup, depth + 1);
    }
}

fn print_entries(group: &database::WrappedPwGroup, depth: u32) {
    for entry in group.borrow().entries.iter() {
        println!("{}@ {}", depth_str(depth), entry.borrow().strings.get("Title").map(ProtectedString::get).unwrap_or("[[ NULL ]]"));
        println!("{}\tUserName = {}", depth_str(depth), entry.borrow().strings.get("UserName").map(ProtectedString::get).unwrap_or("[[ NULL ]]"));
        println!("{}\tPassword = {}", depth_str(depth), entry.borrow().strings.get("Password").map(ProtectedString::get).unwrap_or("[[ NULL ]]"));
        println!("{}\t     URL = {}", depth_str(depth), entry.borrow().strings.get("URL").map(ProtectedString::get).unwrap_or("[[ NULL ]]"));
    }
}

fn depth_str(d: u32) -> String {
    let mut tags = String::with_capacity(d as usize);
    for _ in 0..d {
        tags.push('\t');
    }
    return tags;
}
