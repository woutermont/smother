use oxiri::Iri;
use serde::Deserialize;

enum Identifier {
  Webid(Iri<String>),
}

trait Resource {
  const id: Identifier;
}

struct Agent { 
  id: String,
}

impl Resource for Agent {
  const id: Identifier = Self::id;
}

fn test() {
  let agent = Agent { id: "https://example.com/alice#me".to_string() };
  let webid = match agent.id {
    String => Iri::new(agent.id).unwrap(),
    Identifier::Webid(webid) => webid,
  };
  println!("{}", webid);
}


// enum Identifier {
//   Webid(Iri<String>),
// }

// trait Resource {
//   const id: Identifier;
// }

// struct Agent { 
//   id: String,
// }

// impl Resource for Agent {
//   const id: Identifier = Self::id;
// }

// fn test() {
//   let agent = Agent { id: "https://example.com/alice#me".to_string() };
//   let webid = match agent.id {
//     String => Iri::new(agent.id).unwrap(),
//     Identifier::Webid(webid) => webid,
//   };
//   println!("{}", webid);
// }