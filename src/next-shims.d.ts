declare module 'next/headers' {
  export interface ReadonlyRequestCookie {
    name: string;
    value: string;
  }
  export interface ReadonlyRequestCookies {
    get(name: string): ReadonlyRequestCookie | undefined;
  }
  export function cookies(): Promise<ReadonlyRequestCookies>;
}

declare module 'next/navigation' {
  export function redirect(url: string): never;
}

declare module 'next/server' {
  export const NextResponse: {
    next(): unknown;
    redirect(url: string | URL): unknown;
    json(body: unknown, init?: { status?: number; headers?: Record<string, string> }): unknown;
  };
}
