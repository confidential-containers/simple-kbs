--
-- Below is the encryption key of the encrypted docker image:
--
--     quay.io/kata-containers/encrypted-image-tests:encrypted
--
-- which is used in CI testing of Confidential Containers and simple-kbs
--
INSERT INTO secrets VALUES (10, 'key_id1', 'RcHGava52DPvj1uoIk/NVDYlwxi0A6yyIZ8ilhEX3X4=', NULL);
INSERT INTO keysets VALUES (10, 'KEYSET-1', '["key_id1"]', NULL);
