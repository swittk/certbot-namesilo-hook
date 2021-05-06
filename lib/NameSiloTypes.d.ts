export declare module Namesilo {
    type DNSRecordTypes = "A" | "AAAA" | "CNAME" | "MX" | "TXT";
    interface ResponseRequestField {
        /** The operation performed */
        operation: string[];
        /** The originating IP */
        ip: string[];
    }
    interface ResourceRecord {
        record_id: string[];
        /** The type of the record (A, CNAME, TXT, etc.) */
        type: DNSRecordTypes[];
        /** The string specifying the host for this record (e.g. `*.mydomain.com`, `mydomain.com`, `monkey.mydomain.com`) */
        host: string[];
        /** The value for this record (IP address or text or whatever) */
        value: string[];
        /** TTL */
        ttl: string[];
        /** Distance */
        distance: string[];
    }
    interface Reply {
        code: string[];
        detail: string[];
    }
    type ListDNSRecordReply = Reply & {
        resource_record: ResourceRecord[];
    };
    type AddDNSRecordReply = Reply & {
        record_id: string[];
    };
    interface Namesilo {
        request: ResponseRequestField[];
        reply: Reply[];
    }
    interface APIResponseRootObject {
        namesilo: Namesilo;
    }
}
