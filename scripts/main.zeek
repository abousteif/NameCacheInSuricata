#Scripts to use when you want to enrich Corelight_suricata log with information from the namecache script

module EnrichSuriDNS;

export {
	redef record Suricata::Info += {
		orig_DNSname:  &optional &log;
        resp_DNSname:  &optional &log;
	};
}

event connection_state_remove(c: connection)
{
        if ( c$id$orig_h in name_info_t ) {
                c$conn$id_orig_h_n = name_info_t[c$id$orig_h];
        }
        if ( c$id$resp_h in name_info_t ) {
                c$conn$id_resp_h_n = name_info_t[c$id$resp_h];
        }
c$suricata_alert$orig_DNSname = EnrichSuriDNS::c$conn$id_orig_h_n;
c$suricata_alert$resp_DNSname = EnrichSuriDNS::c$conn$id_resp_h_n;
}
