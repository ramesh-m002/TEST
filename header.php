<?php

// Generate nonce and store it globally
add_action('init', function () {
    if (!defined('WP_CSP_NONCE')) {
        define('WP_CSP_NONCE', base64_encode(random_bytes(16)));
    }
});

// Add nonce attribute to all enqueued scripts
add_filter('script_loader_tag', function ($tag, $handle, $src) {
    if (defined('WP_CSP_NONCE')) {
        if (preg_match('/<script /', $tag)) {
            $tag = str_replace('<script ', '<script nonce="' . esc_attr(WP_CSP_NONCE) . '" ', $tag);
        }
    }
    return $tag;
}, 10, 3);

// Add nonce attribute to all enqueued styles
add_filter('style_loader_tag', function ($tag, $handle, $href, $media) {
    if (defined('WP_CSP_NONCE')) {
        if (preg_match('/<link /', $tag)) {
            $tag = str_replace('<link ', '<link nonce="' . esc_attr(WP_CSP_NONCE) . '" ', $tag);
        }
    }
    return $tag;
}, 10, 4);

// Add CSP headers using the generated nonce
add_action('send_headers', function () {
    if (defined('WP_CSP_NONCE')) {
        $nonce = WP_CSP_NONCE;

        $csp = "
            Content-Security-Policy:
            base-uri 'self';
            form-action 'self' https://www.facebook.com/tr/;
            frame-ancestors 'self';
            connect-src 'self' https://cdn.cookielaw.org https://www.googletagmanager.com https://cdnjs.cloudflare.com https://www.google-analytics.com https://www.googleadservices.com https://stats.g.doubleclick.net https://translate.googleapis.com https://cdn.linkedin.oribi.io https://ad.doubleclick.net https://pagead2.googlesyndication.com https://tags.srv.stackadapt.com https://px.ads.linkedin.com/ https://adservice.google.com/ https://www.google.com https://www.facebook.com;
            default-src 'self';
            font-src 'self' https://fonts.gstatic.com data:;
            frame-src 'self' https://www.google.com https://www.youtube.com https://www.facebook.com https://player.vimeo.com https://9815470.fls.doubleclick.net https://td.doubleclick.net https://go.flightsafety.com/ https://www.googletagmanager.com;
            img-src 'self' data: https://www.gstatic.com https://www.google.com https://www.google-analytics.com/collect https://px.ads.linkedin.com https://p.adsymptotic.com https://cdn.cookielaw.org https://www.linkedin.com https://fonts.gstatic.com https://googleads.g.doubleclick.net https://www.facebook.com https://ad.doubleclick.net https://di.rlcdn.com https://d.agkn.com/ https://www.googletagmanager.com;
            object-src 'none';
            script-src 'self' 'nonce-{$nonce}' 'unsafe-eval' https://cdn.cookielaw.org https://www.googletagmanager.com https://cdnjs.cloudflare.com https://www.google-analytics.com https://www.googleadservices.com https://translate.googleapis.com https://script.crazyegg.com https://snap.licdn.com https://connect.facebook.net https://tags.srv.stackadapt.com https://player.vimeo.com https://go.flightsafety.com;
            style-src 'self' 'nonce-{$nonce}' https://fonts.googleapis.com https://cdn.cookielaw.org https://www.googletagmanager.com https://translate.googleapis.com https://www.gstatic.com;
        ";

        // Remove old header to prevent duplicates
        header_remove('Content-Security-Policy');
        header($csp);
    }
});