declare module 'httpx' {
  type RequestOptions = {
    method?: string;
    data?: Buffer | Uint8Array | string | null;
    headers?: Record<string, string | number>;
    [key: string]: unknown;
  };

  type Response = {
    headers: Record<string, string | undefined>;
  };

  export function request(url: string, options?: RequestOptions): Promise<Response>;
  export function read(response: Response, encoding?: string): Promise<string>;
}
