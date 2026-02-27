/**
 * VoidNote SDK — TypeScript/Node.js
 *
 * npm install voidnote
 *
 * Works in Node.js 18+, Deno, Bun, Cloudflare Workers, and modern browsers
 * (anything with Web Crypto API + fetch).
 */
export interface ReadResult {
    content: string;
    title: string | null;
    viewCount: number;
    maxViews: number;
    destroyed: boolean;
}
export interface CreateOptions {
    title?: string;
    maxViews?: number;
    apiKey: string;
}
export interface CreateResult {
    url: string;
    expiresAt: string;
}
/**
 * Read a VoidNote. Consumes one view — the note may be destroyed after this call.
 *
 * @param urlOrToken  Full VoidNote URL or raw 64-char hex token
 * @param base        Override the base URL (default: https://voidnote.net)
 */
export declare function read(urlOrToken: string, base?: string): Promise<ReadResult>;
/**
 * Create a VoidNote. Requires an API key from your dashboard.
 * Encrypts the content client-side — the server never sees the plaintext.
 *
 * @param content   The secret text to encrypt and store
 * @param options   { apiKey, title?, maxViews? }
 * @param base      Override the base URL (default: https://voidnote.net)
 */
export declare function create(content: string, options: CreateOptions, base?: string): Promise<CreateResult>;
//# sourceMappingURL=index.d.ts.map