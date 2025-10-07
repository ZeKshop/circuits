use dep::string_search::{StringBody, SubString, SubString128, SubString64};
use dep::zkemail::{dkim::RSAPubkey, KEY_LIMBS_2048};

global MAX_PARTIAL_EMAIL_BODY_LENGTH: u32 = 24000;
global MAX_EMAIL_HEADER_LENGTH: u32 = 1344;
global MAX_EMAIL_ADDRESS_LENGTH: u32 = 60;
global MAX_PRODUCT_NAME_LENGTH: u32 = 100;
global TARGET_LENGTH: u32 = 18;
global TARGET: [u8; TARGET_LENGTH] =
    [111, 114, 100, 101, 114, 115, 64, 122, 101, 107, 115, 104, 111, 112, 46, 120, 121, 122];
global PAYMENT_CONFIRMATION_STRING_LENGTH: u32 = 17;

type StringBody1280 = StringBody<1302, 42, 1280>;
type StringBody1408 = StringBody<1426, 46, 1408>;

fn main(
    header: BoundedVec<u8, MAX_EMAIL_HEADER_LENGTH>,
    header_length: u32,
    body: BoundedVec<u8, MAX_PARTIAL_EMAIL_BODY_LENGTH>,
    pubkey: RSAPubkey<KEY_LIMBS_2048>,
    signature: [Field; KEY_LIMBS_2048],
    payment_confirmation: [u8; PAYMENT_CONFIRMATION_STRING_LENGTH],
    payment_confirmation_length: u32,
    product_name: [u8; MAX_PRODUCT_NAME_LENGTH],
    product_name_length: u32,
    from_email_address: [u8; TARGET_LENGTH],
    from_email_address_length: u32,
    to_email_address: [u8; MAX_EMAIL_ADDRESS_LENGTH],
    to_email_address_length: u32,
) {
    verify_purchase(
        header,
        header_length,
        body,
        pubkey,
        signature,
        payment_confirmation,
        payment_confirmation_length,
        product_name,
        product_name_length,
        from_email_address,
        from_email_address_length,
        to_email_address,
        to_email_address_length,
    )
}

fn verify_purchase(
    header: BoundedVec<u8, MAX_EMAIL_HEADER_LENGTH>,
    header_length: u32,
    body: BoundedVec<u8, MAX_PARTIAL_EMAIL_BODY_LENGTH>,
    pubkey: RSAPubkey<KEY_LIMBS_2048>,
    signature: [Field; KEY_LIMBS_2048],
    payment_confirmation: [u8; PAYMENT_CONFIRMATION_STRING_LENGTH],
    payment_confirmation_length: u32,
    product_name: [u8; MAX_PRODUCT_NAME_LENGTH],
    product_name_length: u32,
    from_email_address: [u8; TARGET_LENGTH],
    from_email_address_length: u32,
    to_email_address: [u8; MAX_EMAIL_ADDRESS_LENGTH],
    to_email_address_length: u32,
) {
    // Check that the header's length is within bounds
    assert(header.len() <= MAX_EMAIL_HEADER_LENGTH);

    // Verify the dkim signature over the header
    pubkey.verify_dkim_signature(header, signature);

    // Construct haystack from header to search for substrings
    let haystack: StringBody1280 = StringBody::new(body.storage, body.len);

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

    assert_payment_confirmation_in_body(
        haystack,
        payment_confirmation,
        payment_confirmation_length,
    );

    assert_product_name_in_body(haystack, product_name, product_name_length);
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
    email_address: [u8; 18],
    email_address_length: u32,
) {
    let email_addr: SubString64 = SubString::new(email_address, email_address_length);

    let header_haystack: StringBody1408 = StringBody::new(header.storage, header_length);
    let (email_found, _): (bool, u32) = header_haystack.substring_match(email_addr);

    assert(email_found, "header does not contain email address.");
    assert(email_address == TARGET, "the input email address doesn't match the target address.");
}

fn assert_payment_confirmation_in_body(
    haystack: StringBody1280,
    payment_confirmation: [u8; PAYMENT_CONFIRMATION_STRING_LENGTH],
    payment_confirmation_length: u32,
) {
    let payment_confirmation_substring: SubString128 =
        SubString::new(payment_confirmation, payment_confirmation_length);
    let (match_found2, _): (bool, u32) = haystack.substring_match(payment_confirmation_substring);

    assert(match_found2, "body does not contain payment confirmation");
}

fn assert_product_name_in_body(
    haystack: StringBody1280,
    product_name: [u8; MAX_PRODUCT_NAME_LENGTH],
    product_name_length: u32,
) {
    let product_name_substring: SubString128 = SubString::new(product_name, product_name_length);
    let (match_found2, _): (bool, u32) = haystack.substring_match(product_name_substring);

    assert(match_found2, "body does not contain this product");
}
