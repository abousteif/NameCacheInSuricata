#Scripts to use when you want to enrich Corelight_suricata log with information from the namecache script

module Transcontinental;

type Idx: record {
    info: addr;
};

event connection_state_remove(c: connection)
{
        if ( c$id$orig_h in name_info_t ) {
                c$conn$id_orig_h_n = name_info_t[c$id$orig_h];
        }
        if ( c$id$resp_h in name_info_t ) {
                c$conn$id_resp_h_n = name_info_t[c$id$resp_h];
        }
}
