use fake::{Dummy, Fake, Faker};
use fake::rand::rngs::StdRng;
use fake::rand::SeedableRng;

fn main() {
    for user_id in 1..10 {
        let mut rng = StdRng::seed_from_u64(user_id);
        let username: String = Faker.fake_with_rng(&mut rng);
        let password: String = Faker.fake_with_rng(&mut rng);
        let email: String = Faker.fake_with_rng(&mut rng);
        let passkey: String = Faker.fake_with_rng(&mut rng);
    }
}
