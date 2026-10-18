// ─── record_payment requires a listed resource (#791) ────────────────────────

fn try_record(
    env: &Env,
    client: &VaultRegistryClient,
    settler: &Address,
    payer: &Address,
    id: &String,
    receipt: &str,
    tx: &str,
) -> Result<Result<(), soroban_sdk::ConversionError>, Result<Error, soroban_sdk::InvokeError>> {
    client.try_record_payment(
        settler,
        &String::from_str(env, receipt),
        id,
        payer,
        &100i128,
        &String::from_str(env, tx),
    )
}

#[test]
fn record_payment_rejects_frozen_and_delisted_resources() {
    let (env, creator, _admin, settler, client) = setup_with_settler();
    let id = register_default(&env, &creator, &client, "payfrozen");
    let payer = Address::generate(&env);

    client.freeze_resource(&id);
    assert_eq!(
        try_record(&env, &client, &settler, &payer, &id, "rcptfz1", "0xfz1"),
        Err(Ok(Error::ResourceNotMutable))
    );
    assert_eq!(
        client.try_get_payment(&String::from_str(&env, "rcptfz1")),
        Err(Ok(Error::NotFound))
    );

    client.reactivate_resource(&id);
    client.delist(&id);
    assert_eq!(
        try_record(&env, &client, &settler, &payer, &id, "rcptdl1", "0xdl1"),
        Err(Ok(Error::ResourceNotMutable))
    );

    // Relisted: payments flow again.
    client.set_listed(&id, &true);
    assert!(try_record(&env, &client, &settler, &payer, &id, "rcptok1", "0xok1").is_ok());
    assert_eq!(
        client.get_payment(&String::from_str(&env, "rcptok1")).state,
        PaymentState::Escrowed
    );
}

#[test]
fn record_payment_rejects_disputed_and_tombstoned_resources() {
    let (env, creator, admin, settler, client) = setup_with_settler();
    let id = register_default(&env, &creator, &client, "paydisp");
    let payer = Address::generate(&env);

    client.open_dispute(&id, &admin);
    assert_eq!(
        try_record(&env, &client, &settler, &payer, &id, "rcptdp1", "0xdp1"),
        Err(Ok(Error::ResourceNotMutable))
    );
    client.resolve_dispute(&id, &admin, &ResourceState::Listed);
    assert!(try_record(&env, &client, &settler, &payer, &id, "rcptdp2", "0xdp2").is_ok());

    client.tombstone_resource(&id, &admin);
    assert_eq!(
        try_record(&env, &client, &settler, &payer, &id, "rcptdp3", "0xdp3"),
        Err(Ok(Error::ResourceNotMutable))
    );
}

#[test]
fn listed_check_runs_after_not_found_and_before_price_mismatch() {
    let (env, creator, _admin, settler, client) = setup_with_settler();
    let id = register_default(&env, &creator, &client, "payorder");
    let payer = Address::generate(&env);
    client.freeze_resource(&id);

    // A wrong amount on a frozen resource reports the state, not the price.
    let res = client.try_record_payment(
        &settler,
        &String::from_str(&env, "rcptord1"),
        &id,
        &payer,
        &999i128,
        &String::from_str(&env, "0xord1"),
    );
    assert_eq!(res, Err(Ok(Error::ResourceNotMutable)));

    // An unknown resource still reports NotFound first.
    assert_eq!(
        try_record(
            &env,
            &client,
            &settler,
            &payer,
            &String::from_str(&env, "nosuchpay"),
            "rcptord2",
            "0xord2"
        ),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn idempotent_retry_of_a_recorded_receipt_survives_a_later_freeze() {
    let (env, creator, _admin, settler, client) = setup_with_settler();
    let id = register_default(&env, &creator, &client, "payretry");
    let payer = Address::generate(&env);
    let receipt = String::from_str(&env, "rcptrt1");
    let tx = String::from_str(&env, "0xrt1");

    let first = client.record_payment_idempotent(&settler, &receipt, &id, &payer, &100i128, &tx);
    client.freeze_resource(&id);

    // The stored receipt is returned unchanged; only new receipts are gated.
    let again = client.record_payment_idempotent(&settler, &receipt, &id, &payer, &100i128, &tx);
    assert_eq!(again, first);
    assert_eq!(
        client.try_record_payment_idempotent(
            &settler,
            &String::from_str(&env, "rcptrt2"),
            &id,
            &payer,
            &100i128,
            &String::from_str(&env, "0xrt2"),
        ),
        Err(Ok(Error::ResourceNotMutable))
    );
}

#[test]
fn payment_receipt_page_returns_empty_when_no_purchases() {
    let (env, _creator, _admin, _settler, client) = setup_with_settler();
    let buyer = Address::generate(&env);

    let page = client.payment_receipt_page(&buyer, &None, &0u32, &10u32);
    assert_eq!(page.items.len(), 0u32);
    assert_eq!(page.next_cursor, None);

    let id = String::from_str(&env, "some_res");
    let page_res = client.payment_receipt_page(&buyer, &Some(id), &0u32, &10u32);
    assert_eq!(page_res.items.len(), 0u32);
    assert_eq!(page_res.next_cursor, None);
}

#[test]
fn payment_receipt_page_filters_by_buyer_and_resource_with_deterministic_pagination() {
    let (env, creator, _admin, settler, client) = setup_with_settler();
    let id_a = register_default(&env, &creator, &client, "payflta");
    let id_b = register_default(&env, &creator, &client, "payfltb");

    let buyer1 = Address::generate(&env);
    let buyer2 = Address::generate(&env);

    // Record 5 payments for buyer1 on id_a.
    for i in 0..5u32 {
        let rcpt = String::from_str(&env, &format!("b1_a_{i}"));
        let tx = String::from_str(&env, &format!("tx_b1_a_{i}"));
        client.record_payment(&settler, &rcpt, &id_a, &buyer1, &100i128, &tx);
    }

    // Record 3 payments for buyer1 on id_b.
    for i in 0..3u32 {
        let rcpt = String::from_str(&env, &format!("b1_b_{i}"));
        let tx = String::from_str(&env, &format!("tx_b1_b_{i}"));
        client.record_payment(&settler, &rcpt, &id_b, &buyer1, &100i128, &tx);
    }

    // Record 2 payments for buyer2 on id_a.
    for i in 0..2u32 {
        let rcpt = String::from_str(&env, &format!("b2_a_{i}"));
        let tx = String::from_str(&env, &format!("tx_b2_a_{i}"));
        client.record_payment(&settler, &rcpt, &id_a, &buyer2, &100i128, &tx);
    }

    // 1. Query buyer1 all receipts (resource_id = None), limit = 4
    let page1 = client.payment_receipt_page(&buyer1, &None, &0u32, &4u32);
    assert_eq!(page1.items.len(), 4u32);
    assert_eq!(page1.next_cursor, Some(4u32));

    // Page 2: cursor = 4, limit = 10 (total 8 payments: 5 on A + 3 on B)
    let page2 = client.payment_receipt_page(&buyer1, &None, &4u32, &10u32);
    assert_eq!(page2.items.len(), 4u32);
    assert_eq!(page2.next_cursor, None);

    // 2. Query buyer1 filtered by id_a (resource_id = Some(id_a)), limit = 3
    let page_a1 = client.payment_receipt_page(&buyer1, &Some(id_a.clone()), &0u32, &3u32);
    assert_eq!(page_a1.items.len(), 3u32);
    assert_eq!(page_a1.next_cursor, Some(3u32));
    for item in page_a1.items.iter() {
        assert_eq!(item.resource_id, id_a);
        assert_eq!(item.payer, buyer1);
    }

    // Page 2 of id_a: cursor = 3, limit = 10 (remaining 2)
    let page_a2 = client.payment_receipt_page(&buyer1, &Some(id_a.clone()), &3u32, &10u32);
    assert_eq!(page_a2.items.len(), 2u32);
    assert_eq!(page_a2.next_cursor, None);

    // 3. Query buyer1 filtered by id_b (resource_id = Some(id_b))
    let page_b = client.payment_receipt_page(&buyer1, &Some(id_b.clone()), &0u32, &10u32);
    assert_eq!(page_b.items.len(), 3u32);
    assert_eq!(page_b.next_cursor, None);
    for item in page_b.items.iter() {
        assert_eq!(item.resource_id, id_b);
        assert_eq!(item.payer, buyer1);
    }

    // 4. Query buyer2 filtered by id_a: exactly 2
    let page_buyer2 = client.payment_receipt_page(&buyer2, &Some(id_a.clone()), &0u32, &10u32);
    assert_eq!(page_buyer2.items.len(), 2u32);
    assert_eq!(page_buyer2.next_cursor, None);
    for item in page_buyer2.items.iter() {
        assert_eq!(item.payer, buyer2);
    }

    // 5. Query alias list_payment_receipts_page matches payment_receipt_page
    let alias_page = client.list_payment_receipts_page(&buyer1, &Some(id_b), &0u32, &10u32);
    assert_eq!(alias_page, page_b);
}
