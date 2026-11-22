/**
 * The shared Spurs SSO button and account menu. Import from `@spurs-cloud/accounts/react`.
 *
 * Deliberately styled with inline styles rather than utility classes: a package
 * shipped in `node_modules` can't rely on the host app's Tailwind content scan,
 * so this renders identically in every Spurs app regardless of its CSS setup.
 * The accent is a fallback for users without a profile picture.
 */
import { type CSSProperties, type ReactNode } from "react";
import type { SpursUser } from "./types.js";
export interface SpursAccountMenuProps {
    /** The signed-in user. Omit it to render a "Sign in with Spurs" button. */
    user?: Pick<SpursUser, "name" | "username" | "email" | "picture"> | null;
    /** Fallback avatar colour (hex). Defaults to Spurs indigo. */
    accent?: string;
    /** Secondary gradient colour. Defaults to a darker shade of `accent`. */
    accentTo?: string;
    /** Accounts base URL. Baked in — override only for dev/staging. */
    issuer?: string;
    /** Where "Sign out" points. Defaults to a full Spurs sign-out. */
    signOutUrl?: string;
    /** Handle sign-out yourself (e.g. POST to your own route). Wins over `signOutUrl`. */
    onSignOut?: () => void;
    /** Where the "Sign in" button sends guests. Defaults to Spurs SSO, returning to the current page. */
    signInUrl?: string;
    /** Avatar diameter in px. Default 36. */
    size?: number;
    /** Popover alignment. Default "right". */
    align?: "left" | "right";
    /** Dark surface for the popover. */
    theme?: "light" | "dark";
    /** Extra links rendered above "Sign out". */
    children?: ReactNode;
    /** Classes for the root wrapper (layout: margin, order, self-alignment, etc.). */
    className?: string;
    /** Inline styles merged onto the root wrapper. */
    style?: CSSProperties;
    /** Classes for the avatar button. Visual props set inline (e.g. background) need Tailwind's `!` modifier. */
    buttonClassName?: string;
    /** Classes for the popover panel. Visual props set inline (e.g. background) need Tailwind's `!` modifier. */
    popoverClassName?: string;
}
export interface SpursSignInButtonProps {
    /** Where Spurs Accounts sends the user after signing in. Defaults to the current page. */
    returnTo?: string;
    /** Accounts base URL. Baked in — override only for dev/staging. */
    issuer?: string;
    /** Override the button label. */
    children?: ReactNode;
    /** Button colour. Defaults to Spurs indigo. */
    accent?: string;
    /** Extra classes, merged with Tailwind conflict resolution. */
    className?: string;
    /** Inline styles merged over the defaults. */
    style?: CSSProperties;
}
export declare function SpursSignInButton({ returnTo, issuer, children, accent, className, style, }: SpursSignInButtonProps): any;
export declare function SpursAccountMenu({ user, accent, accentTo, issuer, signOutUrl, onSignOut, signInUrl, size, align, theme, children, className, style, buttonClassName, popoverClassName, }: SpursAccountMenuProps): any;
export default SpursAccountMenu;
//# sourceMappingURL=react.d.ts.map