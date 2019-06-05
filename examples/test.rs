use keepass::database;
pub fn main() {
    let mut database = database::PwDatabase::new();
    database.add_user_key(database::UserKey::Password(database::KcpPassword::new("test", false)));
    keepass::kdbx::load_kdbx_file("data/database.kdbx", &mut database).unwrap();
}
