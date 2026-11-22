"use client";
import { jsx as _jsx, Fragment as _Fragment, jsxs as _jsxs } from "react/jsx-runtime";
/**
 * The shared Spurs SSO button and account menu. Import from `@spurs-cloud/accounts/react`.
 *
 * Deliberately styled with inline styles rather than utility classes: a package
 * shipped in `node_modules` can't rely on the host app's Tailwind content scan,
 * so this renders identically in every Spurs app regardless of its CSS setup.
 * The accent is a fallback for users without a profile picture.
 */
import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState, } from "react";
import { cn } from "./cn.js";
import { accountsOrigin, DEFAULT_ISSUER } from "./constants.js";
const DEFAULT_ACCENT = "#6366f1";
/** Space between the avatar and the popover, and the minimum gap to the viewport edge. */
const GAP = 8;
const EDGE = 8;
// useLayoutEffect warns during SSR on React < 19; fall back to useEffect there.
const useIsoLayoutEffect = typeof window !== "undefined" ? useLayoutEffect : useEffect;
const baseOf = (issuer) => accountsOrigin(issuer || DEFAULT_ISSUER);
export function SpursSignInButton({ returnTo, signInPath = "/auth/login", children = "Sign in with Spurs", accent = DEFAULT_ACCENT, className, style, }) {
    const [target, setTarget] = useState(returnTo ?? "/");
    useEffect(() => {
        setTarget(returnTo ?? `${window.location.pathname}${window.location.search}`);
    }, [returnTo]);
    return (_jsx("a", { href: `${signInPath}?return_to=${encodeURIComponent(target)}`, className: cn("spurs-sign-in", className), style: { ...S.signIn, background: accent, ...style }, children: children }));
}
function initialsOf(user) {
    const source = user.name?.trim() || user.email?.trim() || "?";
    // Array.from keeps surrogate pairs (emoji, rarer scripts) intact.
    const parts = source.split(/\s+/).filter(Boolean).map((p) => Array.from(p)[0] ?? "");
    const first = parts[0] ?? "";
    const second = parts[1];
    const letters = second ? first + second : first || "?";
    return letters.toUpperCase();
}
/**
 * Lighten/darken a hex colour by `amount` (-255..255 per channel).
 * Anything that isn't #rgb or #rrggbb (named colours, rgb(), hsl(), var())
 * is returned unchanged rather than turning into "#NaN".
 */
function shade(color, amount) {
    const m = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(color.trim());
    if (!m)
        return color;
    const matched = m[1] ?? "6366f1";
    const hex = matched.length === 3 ? matched.replace(/./g, "$&$&") : matched;
    const num = parseInt(hex, 16);
    const clamp = (v) => Math.max(0, Math.min(255, v));
    const r = clamp((num >> 16) + amount);
    const g = clamp(((num >> 8) & 0xff) + amount);
    const b = clamp((num & 0xff) + amount);
    return `#${((r << 16) | (g << 8) | b).toString(16).padStart(6, "0")}`;
}
/** Profile picture with an initials fallback if the image fails to load. */
function Avatar({ picture, initials }) {
    const [failed, setFailed] = useState(false);
    useEffect(() => setFailed(false), [picture]);
    if (!picture || failed)
        return _jsx(_Fragment, { children: initials });
    return (_jsx("img", { src: picture, alt: "", referrerPolicy: "no-referrer", onError: () => setFailed(true), style: S.avatarImage }));
}
export function SpursAccountMenu({ user, accent = DEFAULT_ACCENT, accentTo, issuer, signOutUrl, onSignOut, signInUrl, size = 36, align = "right", theme = "light", children, className, style, buttonClassName, popoverClassName, }) {
    const [open, setOpen] = useState(false);
    const wrapRef = useRef(null);
    const buttonRef = useRef(null);
    const panelRef = useRef(null);
    const panelId = useId();
    const close = useCallback((restoreFocus = false) => {
        setOpen(false);
        if (restoreFocus)
            buttonRef.current?.focus();
    }, []);
    useEffect(() => {
        if (!open)
            return;
        // pointerdown covers mouse, touch and pen.
        const onDown = (e) => {
            if (wrapRef.current && !wrapRef.current.contains(e.target))
                close();
        };
        const onKey = (e) => {
            if (e.key === "Escape")
                close(true);
        };
        document.addEventListener("pointerdown", onDown);
        document.addEventListener("keydown", onKey);
        return () => {
            document.removeEventListener("pointerdown", onDown);
            document.removeEventListener("keydown", onKey);
        };
    }, [open, close]);
    // Don't reopen on its own if the user signs out and back in.
    useEffect(() => {
        if (!user)
            setOpen(false);
    }, [user]);
    // Position the popover against the viewport instead of its parent. It stays
    // on screen (clamped horizontally, flipped above the avatar when there's no
    // room below, scrolls internally if the viewport is tiny), isn't clipped by
    // `overflow: hidden` ancestors, and is placed before first paint (no flash).
    useIsoLayoutEffect(() => {
        const button = buttonRef.current;
        const panel = panelRef.current;
        if (!open || !button || !panel)
            return;
        const place = () => {
            // `position: fixed` is relative to the viewport unless an ancestor has a
            // transform, filter or backdrop-filter (common on sticky navbars). Park
            // the panel at 0,0 to measure where the real origin is, then correct for it.
            panel.style.top = "0px";
            panel.style.left = "0px";
            panel.style.maxHeight = "";
            const origin = panel.getBoundingClientRect();
            const anchor = button.getBoundingClientRect();
            const vw = document.documentElement.clientWidth;
            const vh = window.visualViewport?.height ?? window.innerHeight;
            const { width, height } = origin;
            const spaceBelow = vh - anchor.bottom - GAP - EDGE;
            const spaceAbove = anchor.top - GAP - EDGE;
            const above = height > spaceBelow && spaceAbove > spaceBelow;
            const room = Math.max(120, above ? spaceAbove : spaceBelow);
            const h = Math.min(height, room);
            const wantLeft = align === "left" ? anchor.left : anchor.right - width;
            const left = Math.max(EDGE, Math.min(wantLeft, vw - width - EDGE));
            const top = above ? anchor.top - GAP - h : anchor.bottom + GAP;
            if (height > room)
                panel.style.maxHeight = `${room}px`;
            panel.style.left = `${left - origin.left}px`;
            panel.style.top = `${top - origin.top}px`;
            panel.style.visibility = "visible";
        };
        place();
        window.addEventListener("resize", place);
        window.addEventListener("scroll", place, true); // capture: any scrolling ancestor
        window.visualViewport?.addEventListener("resize", place);
        window.visualViewport?.addEventListener("scroll", place);
        const ro = typeof ResizeObserver !== "undefined" ? new ResizeObserver(place) : null;
        ro?.observe(panel);
        ro?.observe(button);
        return () => {
            window.removeEventListener("resize", place);
            window.removeEventListener("scroll", place, true);
            window.visualViewport?.removeEventListener("resize", place);
            window.visualViewport?.removeEventListener("scroll", place);
            ro?.disconnect();
        };
    }, [open, align, size]);
    // Close the popover when any link or button inside it is activated, so
    // same-page links and custom `children` don't leave it hanging open.
    const onPanelClick = (e) => {
        if (e.target.closest("a, button"))
            close();
    };
    if (!user) {
        // An explicit signInUrl wins; otherwise use the button that carries return_to.
        return signInUrl ? (_jsx("a", { href: signInUrl, className: cn("spurs-sign-in", className), style: { ...S.signIn, background: accent, ...style }, children: "Sign in with Spurs" })) : (_jsx(SpursSignInButton, { accent: accent, className: className, style: style }));
    }
    const base = baseOf(issuer);
    const accountUrl = `${base}/me`;
    const outUrl = signOutUrl ?? "/auth/logout";
    const gradient = `linear-gradient(135deg, ${accent}, ${accentTo ?? shade(accent, -28)})`;
    const dark = theme === "dark";
    const surface = dark ? "#18181b" : "#ffffff";
    const border = dark ? "#3f3f46" : "#e5e7eb";
    const text = dark ? "#fafafa" : "#111827";
    const muted = dark ? "#a1a1aa" : "#6b7280";
    const initials = initialsOf(user);
    const label = user.name || user.email || "Spurs account";
    return (_jsxs("div", { ref: wrapRef, className: cn("spurs-account-menu", className), style: { ...S.wrap, ...style }, children: [_jsx("button", { ref: buttonRef, type: "button", className: cn("spurs-account-menu__button", buttonClassName), "aria-expanded": open, "aria-controls": open ? panelId : undefined, "aria-label": `Spurs account: ${label}`, onClick: () => setOpen((v) => !v), style: { ...S.avatarBtn, width: size, height: size, background: gradient, fontSize: size * 0.4 }, children: _jsx(Avatar, { picture: user.picture, initials: initials }) }), open && (
            // Disclosure pattern: a plain panel of links. `role="menu"` would
            // promise arrow-key navigation and menuitem children we don't provide.
            _jsxs("div", { id: panelId, ref: panelRef, className: cn("spurs-account-menu__popover", popoverClassName), onClick: onPanelClick, style: {
                    ...S.popover,
                    background: surface,
                    borderColor: border,
                    color: text,
                    // Real coordinates are written by the layout effect above.
                    top: 0,
                    left: 0,
                    visibility: "hidden",
                }, children: [_jsxs("div", { style: { ...S.header, borderColor: border }, children: [_jsx("div", { style: { ...S.bigAvatar, background: gradient }, children: _jsx(Avatar, { picture: user.picture, initials: initials }) }), _jsx("div", { style: S.name, children: user.name || "Your account" }), user.username && _jsxs("div", { style: { ...S.username, color: muted }, children: ["@", user.username] }), user.email && _jsx("div", { style: { ...S.email, color: muted }, children: user.email }), _jsx("a", { href: accountUrl, style: { ...S.manage, borderColor: border, color: text }, children: "Manage your Spurs Account" })] }), children, onSignOut ? (_jsx("button", { type: "button", onClick: onSignOut, style: { ...S.item, ...S.signOut, width: "100%", textAlign: "left" }, children: "Sign out" })) : (_jsx("a", { href: outUrl, style: { ...S.item, ...S.signOut }, children: "Sign out" }))] }))] }));
}
const S = {
    wrap: { position: "relative", display: "inline-block" },
    avatarBtn: {
        display: "grid",
        placeItems: "center",
        borderRadius: "9999px",
        border: "none",
        color: "#fff",
        fontWeight: 600,
        cursor: "pointer",
        padding: 0,
        lineHeight: 1,
        fontFamily: "inherit",
        overflow: "hidden",
        flexShrink: 0,
    },
    signIn: {
        display: "inline-flex",
        alignItems: "center",
        borderRadius: 8,
        padding: "8px 14px",
        color: "#fff",
        fontSize: 14,
        fontWeight: 500,
        textDecoration: "none",
        fontFamily: "inherit",
    },
    popover: {
        position: "fixed",
        width: 288,
        maxWidth: "calc(100vw - 16px)",
        borderRadius: 16,
        border: "1px solid",
        boxShadow: "0 12px 32px rgba(0,0,0,.16)",
        overflowX: "hidden",
        overflowY: "auto",
        overscrollBehavior: "contain",
        zIndex: 50,
        fontFamily: "inherit",
    },
    header: {
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 6,
        padding: "20px 20px 18px",
        borderBottom: "1px solid",
    },
    bigAvatar: {
        display: "grid",
        placeItems: "center",
        width: 56,
        height: 56,
        borderRadius: "9999px",
        color: "#fff",
        fontSize: 20,
        fontWeight: 600,
        overflow: "hidden",
    },
    avatarImage: {
        display: "block",
        width: "100%",
        height: "100%",
        borderRadius: "inherit",
        objectFit: "cover",
    },
    name: { fontSize: 14, fontWeight: 500, marginTop: 4, maxWidth: "100%", overflowWrap: "anywhere", textAlign: "center" },
    username: { fontSize: 12, maxWidth: "100%", overflowWrap: "anywhere", textAlign: "center" },
    email: { fontSize: 12, maxWidth: "100%", overflowWrap: "anywhere", textAlign: "center" },
    manage: {
        marginTop: 8,
        display: "inline-block",
        borderRadius: 9999,
        border: "1px solid",
        padding: "6px 16px",
        fontSize: 12,
        fontWeight: 500,
        textDecoration: "none",
    },
    item: {
        display: "block",
        padding: "12px 20px",
        fontSize: 14,
        textDecoration: "none",
        background: "none",
        border: "none",
        cursor: "pointer",
        fontFamily: "inherit",
    },
    signOut: { color: "#dc2626" },
};
export default SpursAccountMenu;
//# sourceMappingURL=react.js.map