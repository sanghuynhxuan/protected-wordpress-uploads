<?php
/**
 * Plugin Name: KiviCare Private Custom-Field Uploads
 * Description: Di chuyển file custom-field KiviCare vào kc-private và serve có kiểm tra quyền.
 * Version: 1.0
 * Author: bạn
 */

define('KC_PRIVATE_DIR', 'kc-private');

/* 1) TỰ ĐỘNG TẠO THƯ MỤC kc-private VÀ .htaccess */
add_action('init', 'kc_private_setup');
function kc_private_setup(){
    $u = wp_upload_dir();
    $private = $u['basedir'].'/'.KC_PRIVATE_DIR;
    if(!file_exists($private)){
        if(!wp_mkdir_p($private)){
            error_log('KiviCare error: Cannot create kc-private directory');
            return;
        }
    }
    $ht = $private.'/.htaccess';
    if(!file_exists($ht)){
        $c = "RewriteEngine On\nRewriteRule ^(.*)$ /?kc_private_file=$1 [QSA,L]\n";
        if(!file_put_contents($ht, $c)){
            error_log('KiviCare error: Cannot create .htaccess file');
        }
    }
}

/* 2) SAU KHI KIVICARE LƯU Encounter/Patient → di chuyển file vào kc-private */
add_action('kc_encounter_update', 'kc_move_kc_file', 20);
add_action('kc_patient_update', 'kc_move_kc_file', 20);
function kc_move_kc_file($module_id){
    if(!$module_id || !current_user_can('manage_options')) return;
    global $wpdb;
    $u = wp_upload_dir();
    $private = $u['basedir'].'/'.KC_PRIVATE_DIR;
    $table = $wpdb->prefix.'kc_custom_fields_data';
    $rows = $wpdb->get_results($wpdb->prepare(
        "SELECT fields_data 
           FROM $table 
          WHERE module_type IN ('patient_encounter_module','patient_module')
            AND module_id = %d
            AND fields_data LIKE %s",
        $module_id,
        '%"url":"%'
    ));
    foreach($rows as $r){
        $d = json_decode($r->fields_data, true);
        if(empty($d['id']) || empty($d['url'])) continue;
        $aid = (int)$d['id'];
        $orig = get_attached_file($aid);
        if(!file_exists($orig)) continue;
        $sub = str_replace($u['basedir'], '', dirname($orig));
        $dest_dir = $private . $sub;
        wp_mkdir_p($dest_dir);
        $new = $dest_dir.'/'.basename($orig);
        if(@rename($orig, $new)){
            update_post_meta($aid, '_wp_attached_file', KC_PRIVATE_DIR.$sub.'/'.basename($orig));
        } else {
            error_log("KiviCare error: Failed to move file $orig to $new");
        }
    }
}

/* 3) Thêm rewrite rule & query_var để catch yêu cầu kc-private */
register_activation_hook(__FILE__, function(){
    add_rewrite_rule('^wp-content/uploads/'.KC_PRIVATE_DIR.'/(.+)$', 'index.php?kc_private_file=$1', 'top');
    flush_rewrite_rules();
    update_option('kc_private_rewrite_flushed', 1);
});
add_filter('query_vars', function($q){ $q[] = 'kc_private_file'; return $q; });
add_action('init', function(){
    add_rewrite_rule('^wp-content/uploads/'.KC_PRIVATE_DIR.'/(.+)$', 'index.php?kc_private_file=$1', 'top');
});

/* 4) Serve file với kiểm tra quyền */
add_action('template_redirect', function(){
    global $wpdb;
    $file = sanitize_text_field(get_query_var('kc_private_file'));
    $file = str_replace('..', '', $file); // Ngăn path traversal
    if(!$file) return;
    $u = wp_upload_dir();
    $path = $u['basedir'].'/'.KC_PRIVATE_DIR.'/'.$file;
    if(!file_exists($path)){ status_header(404); exit; }
    if(!is_user_logged_in()){ auth_redirect(); }
    $aid = $wpdb->get_var($wpdb->prepare(
        "SELECT post_id FROM $wpdb->postmeta WHERE meta_key=%s AND meta_value=%s",
        '_wp_attached_file', KC_PRIVATE_DIR.'/'.$file
    ));
    if(!$aid || get_post_type($aid) !== 'attachment'){ status_header(403); exit; }
    $pid = kc_get_patient_id_from_attachment($aid);
    if(!kc_check_file_access($aid, $pid)){ status_header(403); exit; }
    $allowed_mimes = ['image/jpeg', 'image/png', 'application/pdf', 'text/plain'];
    $mime = mime_content_type($path);
    if(!in_array($mime, $allowed_mimes)){ status_header(403); exit; }
    header('Content-Type: '.$mime);
    header('Content-Length: '.filesize($path));
    readfile($path);
    exit;
});

/* ——— Helper functions ——— */
function kc_check_file_access($aid, $pid){
    $role = kc_get_current_user_role();
    $uid = get_current_user_id();
    if(in_array($role, ['administrator', 'clinicadmin', 'receptionist'])){
        return true;
    } elseif($role === 'doctor'){
        return kc_doctor_can_access_patient($uid, $pid);
    } elseif($role === 'patient'){
        return kc_patient_owns_file($uid, $aid);
    }
    return false;
}

function kc_get_current_user_role(){
    $r = wp_get_current_user()->roles;
    return empty($r) ? '' : $r[0];
}

function kc_patient_owns_file($patient_id, $aid){
    $owner = (int)get_post_field('post_author', $aid);
    return $owner === (int)$patient_id;
}

function kc_doctor_can_access_patient($doctor_id, $patient_id){
    if(!$patient_id) return false;
    if(!function_exists('kcDoctorPatientList')){
        error_log('KiviCare error: kcDoctorPatientList function not found');
        return false;
    }
    $arr = kcDoctorPatientList($doctor_id);
    return in_array($patient_id, $arr);
}

function kc_get_patient_id_from_attachment($aid){
    global $wpdb;
    if(get_post_type($aid) !== 'attachment') return 0;
    $eid = (int)get_post_meta($aid, 'encounter_id', true);
    if($eid){
        $pid = (int)$wpdb->get_var($wpdb->prepare(
            "SELECT patient_id FROM {$wpdb->prefix}kc_patient_encounters WHERE id=%d", $eid
        ));
        if($pid) return $pid;
    }
    $pid2 = (int)get_post_meta($aid, 'attached_patient_id', true);
    if($pid2) return $pid2;
    return 0;
}