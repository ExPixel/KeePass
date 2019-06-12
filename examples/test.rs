use keepass::database;

pub fn main() {
    println!("sizeof: {} bytes", std::mem::size_of::<database::PwDatabase>());

    let mut database = database::PwDatabase::new();
    database.add_user_key(database::UserKey::Password(database::KcpPassword::new("test", false)));
    keepass::kdbx::load_kdbx_file("data/database.kdbx", keepass::kdbx::KdbxFormat::Default, &mut database).unwrap();
}
