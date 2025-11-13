<?php

/**
 * Plugin Name:       FS-CSP-NONCE
 * Plugin URI:        https://tsw.ovh/
 * Description:       Add a nonce to each script and style tag, and set those nonces in CSP header
 * Version:           1.5.2
 * Requires at least: 5.9
 * Requires PHP:      7.3
 * Author:            flightsafety
 * License:           GPL v3
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly
}

if ( function_exists( 'litespeed_autoload' ) ) :

    // LSCACHE version
    function flightsafety_cspantsst_lscwp_check( $content ) {

        $uris = implode( ' ', flightsafety_cspantsst_search_for_sources( $content ) );
        $sha256_csp = flightsafety_cspantsst_search_for_events( $content );
        $nonces = [];

        $content = preg_replace_callback( '#<script.*?>#', function( $matches ) use ( &$nonces ) {
            $nonce = wp_create_nonce( $matches[0] );
            $nonces[] = $nonce;
            return str_replace( '<script', "<script nonce='{$nonce}'", $matches[0] );
        }, $content );

        $content = preg_replace_callback( '#<style.*?>#', function( $matches ) use ( &$nonces ) {
            $nonce = wp_create_nonce( $matches[0] );
            $nonces[] = $nonce;
            return str_replace( '<style', "<style nonce='{$nonce}'", $matches[0] );
        }, $content );

        $nonces_csp = array_reduce( $nonces, function( $header, $nonce ) {
            return "{$header} 'nonce-{$nonce}'";
        }, '' );

        header( sprintf(
            "Content-Security-Policy: base-uri 'self' %1\$s data:; object-src 'none'; script-src https:%2\$s %3\$s 'strict-dynamic'",
            $uris, $nonces_csp, $sha256_csp
        ) );

        return $content;
    }

    add_filter( 'litespeed_buffer_after', 'flightsafety_cspantsst_lscwp_check', 0 );

else :

    // Otherwise, generic WP version
    add_action( 'template_redirect', function() {

        ob_start( function( $output ) {

            $uris = implode( ' ', flightsafety_cspantsst_search_for_sources( $output ) );
            $sha256_csp = flightsafety_cspantsst_search_for_events( $output );
            $nonces = [];

            $output = preg_replace_callback( '#<script.*?>#', function( $matches ) use ( &$nonces ) {
                $nonce = wp_create_nonce( $matches[0] );
                $nonces[] = $nonce;
                return str_replace( '<script', "<script nonce='{$nonce}'", $matches[0] );
            }, $output );

            $output = preg_replace_callback( '#<style.*?>#', function( $matches ) use ( &$nonces ) {
                $nonce = wp_create_nonce( $matches[0] );
                $nonces[] = $nonce;
                return str_replace( '<style', "<style nonce='{$nonce}'", $matches[0] );
            }, $output );

            $nonces_csp = array_reduce( $nonces, function( $header, $nonce ) {
                return "{$header} 'nonce-{$nonce}'";
            }, '' );

            header( sprintf(
                "Content-Security-Policy: base-uri 'self' %1\$s data:; object-src 'none'; script-src https:%2\$s %3\$s 'strict-dynamic'",
                $uris, $nonces_csp, $sha256_csp
            ) );

            return $output;
        });
    });

endif;

function flightsafety_cspantsst_search_for_events( $output ) {
    $sha256 = [];

    preg_match_all( '/onload="([^"]+)"|onclick="([^"]+)"/', $output, $matches );
    foreach ( $matches[1] as $match ) {
        if ( ! empty( $match ) ) $sha256[] = base64_encode( hash( 'sha256', $match, true ) );
    }
    foreach ( $matches[2] as $match ) {
        if ( ! empty( $match ) ) $sha256[] = base64_encode( hash( 'sha256', $match, true ) );
    }

    if ( class_exists( 'autoptimizeConfig' ) ) {
        $sha256[] = base64_encode( hash( 'sha256', "this.onload=null;this.media='all';", true ) );
    }

    $header_sha256 = "'unsafe-hashes'";
    $sha256_csp = array_reduce( $sha256, function( $header, $sha256_item ) {
        return "{$header} 'sha256-{$sha256_item}'";
    }, '' );

    if ( ! empty( $sha256_csp ) ) $sha256_csp = $header_sha256 . $sha256_csp;

    return $sha256_csp;
}

function flightsafety_cspantsst_search_for_sources( $string ) {
    $result = [];
    if ( strpos( $string, 'https://secure.gravatar.com/avatar/' ) !== false ) $result[] = 'https://secure.gravatar.com/avatar/';
    if ( strpos( $string, 'https://fonts.googleapis.com/' ) !== false ) $result[] = 'https://fonts.googleapis.com/';
    if ( strpos( $string, 'https://maxcdn.bootstrapcdn.com/' ) !== false ) $result[] = 'https://maxcdn.bootstrapcdn.com/';
    return $result;
}
