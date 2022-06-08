export declare module Namesilo {
  export type DNSRecordTypes = "A" | "AAAA" | "CNAME" | "MX" | "TXT";

  export interface ResponseRequestField {
    /** The operation performed */
    operation: string[];
    /** The originating IP */
    ip: string[];
  }

  export interface ResourceRecord {
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

  export interface Reply {
    code: string[];
    detail: string[];
  }

  export type ListDNSRecordReply = Reply & {
    resource_record: ResourceRecord[];
  }
  export type AddDNSRecordReply = Reply & {
    record_id: string[];
  }
  export type UpdateDNSRecordReply = Reply & {
    record_id: string[];
  }

  export interface Namesilo {
    request: ResponseRequestField[];
    reply: Reply[];
  }

  export interface APIResponseRootObject {
    namesilo: Namesilo;
  }

}

