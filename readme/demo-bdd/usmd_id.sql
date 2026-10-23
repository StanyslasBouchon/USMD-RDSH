-- USMD-RDSH data identifiers [draft-usmd-rdsh-architecture-03, 11.6]
-- The instance's prefix is set by its build sequence:
--   ALTER DATABASE app SET usmd.data_id_prefix = '$USMD_DATA_ID_PREFIX';
-- then: id uuid PRIMARY KEY DEFAULT usmd_id()
CREATE SEQUENCE IF NOT EXISTS usmd_id_seq MINVALUE 0 MAXVALUE 65535 CYCLE;
CREATE OR REPLACE FUNCTION usmd_id() RETURNS uuid LANGUAGE plpgsql VOLATILE AS $$
DECLARE
  prefix text   := current_setting('usmd.data_id_prefix');
  ms     bigint := floor(extract(epoch FROM clock_timestamp()) * 1000);
  seq    bigint := nextval('usmd_id_seq');
  rnd    bigint := floor(random() * 67108864);
BEGIN
  IF prefix !~ '^0[0-9a-f]{7}$' THEN
    RAISE EXCEPTION 'usmd.data_id_prefix: 8 hexadecimal digits';
  END IF;
  RETURN (prefix
    || lpad(to_hex((ms >> 32) & 65535), 4, '0')
    || '8' || lpad(to_hex((ms >> 20) & 4095), 3, '0')
    || lpad(to_hex((2::bigint << 30) | ((ms & 1048575) << 10)
                   | (seq >> 6)), 8, '0')
    || lpad(to_hex(((seq & 63) << 26) | rnd), 8, '0'))::uuid;
END $$;
-- The SP address (sss.nnnn) and creation time of an identifier.
CREATE OR REPLACE FUNCTION usmd_id_sp_address(id uuid) RETURNS text
  LANGUAGE sql IMMUTABLE AS $$
  SELECT substr(id::text, 2, 3) || '.' || substr(id::text, 5, 4) $$;
CREATE OR REPLACE FUNCTION usmd_id_created(id uuid) RETURNS timestamptz
  LANGUAGE sql IMMUTABLE AS $$
  SELECT to_timestamp((('x' || lpad(substr(replace(id::text, '-', ''), 9, 4)
                         || substr(replace(id::text, '-', ''), 14, 3), 16, '0'))::bit(64)::bigint
                       * 1048576
                       + ((('x' || substr(replace(id::text, '-', ''), 17, 8))::bit(32)::bigint
                           >> 10) & 1048575)) / 1000.0) $$;
