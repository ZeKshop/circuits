use dep::string_search::{StringBody, SubString, SubString128, SubString64};
use dep::zkemail::{dkim::RSAPubkey, KEY_LIMBS_2048};

// global MAX_PURCHASE_NUMBER_LENGTH: u32 = 20;

global MAX_EMAIL_HEADER_LENGTH: u32 = 1344;
global MAX_EMAIL_ADDRESS_LENGTH: u32 = 60;
global TARGET_LENGTH: u32 = 19;
global TARGET: [u8; TARGET_LENGTH] =
    [110, 111, 114, 101, 112, 108, 121, 64, 122, 101, 107, 115, 104, 111, 112, 46, 120, 121, 122];
type StringBody1408 = StringBody<1426, 46, 1408>;

fn main(
    header: BoundedVec<u8, MAX_EMAIL_HEADER_LENGTH>,
    header_length: u32,
    pubkey: RSAPubkey<KEY_LIMBS_2048>,
    signature: [Field; KEY_LIMBS_2048],
    from_email_address: [u8; TARGET_LENGTH],
    from_email_address_length: u32,
    to_email_address: [u8; MAX_EMAIL_ADDRESS_LENGTH],
    to_email_address_length: u32,
) {
    verify_purchase(
        header,
        header_length,
        pubkey,
        signature,
        from_email_address,
        from_email_address_length,
        to_email_address,
        to_email_address_length,
    )
}

fn verify_purchase(
    header: BoundedVec<u8, MAX_EMAIL_HEADER_LENGTH>,
    header_length: u32,
    pubkey: RSAPubkey<KEY_LIMBS_2048>,
    signature: [Field; KEY_LIMBS_2048],
    from_email_address: [u8; 19],
    from_email_address_length: u32,
    to_email_address: [u8; MAX_EMAIL_ADDRESS_LENGTH],
    to_email_address_length: u32,
) {
    // Check that the header's length is within bounds
    assert(header.len() <= MAX_EMAIL_HEADER_LENGTH);

    // Verify the dkim signature over the header
    pubkey.verify_dkim_signature(header, signature);

    // Construct haystack from header to search for substrings
    // let haystack: StringBody1280 = StringBody::new(body.storage, body.len);

    // assert_purchase_number_in_body(haystack, purchase_number, purchase_number_length);
    assert_from_address_is_correct(
        header,
        header_length,
        from_email_address,
        from_email_address_length,
    );
    assert_to_email_address_in_header(
        header,
        header_length,
        to_email_address,
        to_email_address_length,
    );
}

fn assert_to_email_address_in_header(
    header: BoundedVec<u8, MAX_EMAIL_HEADER_LENGTH>,
    header_length: u32,
    email_address: [u8; MAX_EMAIL_ADDRESS_LENGTH],
    email_address_length: u32,
) {
    let email_addr: SubString64 = SubString::new(email_address, email_address_length);

    let header_haystack: StringBody1408 = StringBody::new(header.storage, header_length);
    let (email_found, _): (bool, u32) = header_haystack.substring_match(email_addr);

    assert(email_found, "header does not contain email address");
}

fn assert_from_address_is_correct(
    header: BoundedVec<u8, MAX_EMAIL_HEADER_LENGTH>,
    header_length: u32,
    email_address: [u8; 19],
    email_address_length: u32,
) {
    let email_addr: SubString64 = SubString::new(email_address, email_address_length);

    let header_haystack: StringBody1408 = StringBody::new(header.storage, header_length);
    let (email_found, _): (bool, u32) = header_haystack.substring_match(email_addr);

    assert(email_found, "header does not contain email address.");
    assert(email_address == TARGET, "the input email address doesn't match the target address.");
}

// fn assert_purchase_number_in_body(
//     haystack: StringBody1280,
//     purchase_number: [u8; MAX_PURCHASE_NUMBER_LENGTH],
//     purchase_number_length: u32,
// ) {
//     let purchase_number_substring: SubString128 =
//         SubString::new(purchase_number, purchase_number_length);
//     let (match_found2, _): (bool, u32) = haystack.substring_match(purchase_number_substring);

//     assert(match_found2, "header does not contain this purchase number");
// }
