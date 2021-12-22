use {
    criterion::{criterion_group, criterion_main, Criterion},
    threshold_dkg::{
        curve_traits::{ECPoint, ECScalar},
        dkg::DistKeyGenerator,
        dkg::{Deal, Response},
        dss::{verify, DSS},
        ristretto_curve::{FE, GE},
    },
};

#[derive(Debug, Default)]
pub struct Node {
    pub index: usize,
    pub priv_k: FE, // longterm secret, i.e. private key of the node
    pub pub_k: GE,
    pub deals: Vec<Deal>,
    pub resps: Vec<Response>,
    pub dkg: Option<DistKeyGenerator>,
    pub dss: Option<DSS>,
}

impl Node {
    pub fn dkg_mut(&mut self) -> &mut DistKeyGenerator {
        self.dkg.as_mut().expect("No dkg")
    }

    pub fn dkg_ref(&self) -> &DistKeyGenerator {
        self.dkg.as_ref().expect("No dkg")
    }

    pub fn dss_mut(&mut self) -> &mut DSS {
        self.dss.as_mut().expect("No dss")
    }

    pub fn dss_ref(&self) -> &DSS {
        self.dss.as_ref().expect("No dss")
    }
}

fn test_example_dkg() {
    let n_nodes = 7_usize;

    let mut nodes: Vec<Node> = Vec::new();
    let mut pub_keys: Vec<GE> = Vec::new();

    // 1. Init the nodes
    let generator = GE::generator();
    for index in 0..n_nodes {
        let priv_k: FE = ECScalar::new_random();
        let pub_k: GE = generator.scalar_mul(&priv_k.get_element());
        pub_keys.push(pub_k);
        nodes.push(Node {
            index,
            priv_k,
            pub_k,
            ..Default::default()
        });
    }

    // 2. Create the DKGs on each node
    for node in &mut nodes {
        let dkg = DistKeyGenerator::new(node.priv_k, pub_keys.clone(), n_nodes as u32)
            .expect("Failed to create dkg");
        node.dkg = Some(dkg);
    }

    // 3. Each node sends its Deals to the other nodes
    for i in 0..n_nodes {
        let deals = nodes[i].dkg_mut().deals().expect("Failed to create deals");
        for (i, deal) in deals.into_iter() {
            nodes[i as usize].deals.push(deal);
        }
    }

    // 4. Process the Deals on each node and send the responses to the other
    for i in 0..n_nodes {
        let deals = nodes[i].deals.clone();
        let resps = deals
            .iter()
            .map(|deal| nodes[i].dkg_mut().process_deal(&deal))
            .collect::<Result<Vec<_>, _>>()
            .expect("Failed to process some deal");
        for resp in resps {
            for (j, node) in nodes.iter_mut().enumerate() {
                if i != j {
                    node.resps.push(resp.clone());
                }
            }
        }
    }

    // 5. Process the responses on each node
    for node in &mut nodes {
        let resps = node.resps.clone();
        for resp in &resps {
            node.dkg_mut()
                .process_response(resp)
                .expect("Failed to process response");
        }
    }

    // 6. Check if all deals certified
    for node in &nodes {
        assert!(node.dkg_ref().certified());
        assert_eq!(n_nodes, node.dkg_ref().qual().len());
    }

    // 7. Get secret committs and distribute them
    let scs = nodes
        .iter_mut()
        .map(|node| node.dkg_mut().secret_commits())
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to get secret commits");

    for sc in &scs {
        for node in &mut nodes {
            node.dkg_mut()
                .process_secret_commit(sc)
                .expect("Failed to process secret commits");
        }
    }

    // 8. Get distributed key shares, get public key
    let shares = nodes
        .iter()
        .map(|node| node.dkg_ref().dist_key_share())
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to get dist key shares");

    // pub_k is the the same for every share
    let shared_pub_k = shares[0].get_public_key();

    // 9. Create distributed signature service for each node
    let message_to_sign = b"Alice cosigned with Bob";
    for (node, share) in nodes.iter_mut().zip(&shares) {
        node.dss = Some(
            DSS::new(
                node.priv_k,
                pub_keys.clone(),
                share.clone(),
                share.clone(),
                message_to_sign.to_vec(),
                n_nodes as u32,
            )
            .expect("Failed to create dss"),
        );
    }

    // 10. Using DSS, create and distribue partial signatures
    let part_sigs = nodes
        .iter_mut()
        .map(|node| node.dss_mut().partial_sig())
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to get partial signature");

    for (i, part_sig) in part_sigs.iter().enumerate() {
        for (j, node) in nodes.iter_mut().enumerate() {
            if i != j {
                node.dss_mut()
                    .process_partial_sig(part_sig)
                    .expect("Failed to process partial sig");
            }
        }
    }

    // 11. Retrieve shared signature, verify it
    let signature = nodes[0]
        .dss_ref()
        .signature()
        .expect("Failed to get signature");

    let verified = verify(shared_pub_k, message_to_sign, &signature)
        .expect("Failed to verify shared signature");

    assert!(verified);
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("dkg_and_dss", |b| b.iter(test_example_dkg));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
