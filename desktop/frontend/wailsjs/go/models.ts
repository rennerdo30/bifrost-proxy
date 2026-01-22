export namespace main {
	
	export class ProxySettings {
	    server_address: string;
	    server_protocol: string;
	    http_proxy_port: number;
	    socks5_proxy_port: number;
	
	    static createFrom(source: any = {}) {
	        return new ProxySettings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.server_address = source["server_address"];
	        this.server_protocol = source["server_protocol"];
	        this.http_proxy_port = source["http_proxy_port"];
	        this.socks5_proxy_port = source["socks5_proxy_port"];
	    }
	}
	export class QuickSettings {
	    auto_connect: boolean;
	    start_minimized: boolean;
	    show_notifications: boolean;
	    vpn_enabled: boolean;
	    current_server: string;
	
	    static createFrom(source: any = {}) {
	        return new QuickSettings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.auto_connect = source["auto_connect"];
	        this.start_minimized = source["start_minimized"];
	        this.show_notifications = source["show_notifications"];
	        this.vpn_enabled = source["vpn_enabled"];
	        this.current_server = source["current_server"];
	    }
	}
	export class ServerInfo {
	    name: string;
	    address: string;
	    protocol: string;
	    is_default: boolean;
	    latency_ms?: number;
	    status: string;
	
	    static createFrom(source: any = {}) {
	        return new ServerInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.address = source["address"];
	        this.protocol = source["protocol"];
	        this.is_default = source["is_default"];
	        this.latency_ms = source["latency_ms"];
	        this.status = source["status"];
	    }
	}
	export class StatusResponse {
	    status: string;
	    version: string;
	    server_connected: boolean;
	    server_address: string;
	    http_proxy: string;
	    socks5_proxy: string;
	    vpn_enabled: boolean;
	    vpn_status: string;
	    debug_entries: number;
	    uptime: string;
	    bytes_sent: number;
	    bytes_received: number;
	    active_connections: number;
	    last_error?: string;
	    // Go type: time
	    timestamp: any;
	
	    static createFrom(source: any = {}) {
	        return new StatusResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.status = source["status"];
	        this.version = source["version"];
	        this.server_connected = source["server_connected"];
	        this.server_address = source["server_address"];
	        this.http_proxy = source["http_proxy"];
	        this.socks5_proxy = source["socks5_proxy"];
	        this.vpn_enabled = source["vpn_enabled"];
	        this.vpn_status = source["vpn_status"];
	        this.debug_entries = source["debug_entries"];
	        this.uptime = source["uptime"];
	        this.bytes_sent = source["bytes_sent"];
	        this.bytes_received = source["bytes_received"];
	        this.active_connections = source["active_connections"];
	        this.last_error = source["last_error"];
	        this.timestamp = this.convertValues(source["timestamp"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

