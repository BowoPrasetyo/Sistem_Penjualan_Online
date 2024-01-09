<?php
defined('BASEPATH') OR exit('No direct script access allowed');

function resource_url() {
  return base_url() . 'resources/';
}

function validate_self_request() {
  if(parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) != $_SERVER['SERVER_NAME']) {
    redirect(base_url());
    exit;
  }  
}

function check_image($dir, $name, $default = 'https://via.placeholder.com/468')
{
  if(!file_exists('resources/' . $dir . '/' . $name)) {
    return $default;
  }

  return base_url() . 'resources/' . $dir . '/' . $name;
}

function getOpenGraph($matches){
  return strrev($matches[1]);  // just reverse the string for effect
}

function is_payment($status) {
  if($status != 'waiting_transfer' && $status != 'cancel') {
    return true;
  }

  return false;
}

function is_cancel($status) {
  if($status == 'cancel') {
    return true;
  }

  return false;
}

function image_courier($courier)
{
  $logo = '';
  switch($courier) {
    case 'jne':
      $logo = 'img/jne.png';
      break;
    case 'tiki':
      $logo = 'img/tiki.jpg';
      break;
    case 'jnt':
      $logo = 'img/jnt.jpg';
      break;    
  }

  return resource_url() . $logo;
}

function clean_code($string) {
  return strip_tags($string);
}

function is_login_member()
{
  $CI =& get_instance();

  return $CI->session->userdata('user') ? true : false;
}

function uploadGlobalFile($file_name, $dir,$prefix_file,$extension = ''){   
  $CI =& get_instance();

  if (!file_exists($dir)) {
      mkdir($dir, 0777, true);
  }

  $config['upload_path']          = $dir;
  $config['allowed_types']        = $extension != '' ? $extension : 'gif|jpg|png|jpeg|pdf|svg';
  $config['file_name']            = $prefix_file.'_'.date('Yhis') . '_' . time() . '-' . md5(time());
  $config['overwrite']			      = false;
  $config['max_size']             = 10240; // 1MB

  $CI->load->library('upload', $config);

  if ($CI->upload->do_upload($file_name)) {
      return $CI->upload->data("file_name");
  }
  
  return null;
}

function generate_sidebar_menu($sidebar) {
  $menu = '';

  if(count($sidebar['childrens']) > 0) {
    $menu .= '<li class="nav-item has-treeview">';

    if(count($sidebar['childrens']) > 0) {
        $menu .= '<a href="'.$sidebar['link'].'" class="nav-link">
        <i class="nav-icon '.$sidebar['icon'].'"></i>
        <p>
          '.$sidebar['title'].'
          <i class="right fas fa-angle-left"></i>
        </p>
      </a>';

      $menu .= '<ul class="nav nav-treeview">';
      foreach($sidebar['childrens'] as $children) {
        $menu .= '<li class="nav-item">
          <a href="'.$children['link'].'" class="nav-link">
            <i class="nav-icon '.$children['icon'].'"></i>
            <p>'.$children['title'].'</p>
          </a>
        </li>';

        if(count($children['childrens']) > 0) {
          $menu .= generate_sidebar_menu($children);
        }
      }
      $menu .= '</ul>';
    } else {
      $menu .= '<a href="'.$children['link'].'" class="nav-link">
        <i class="nav-icon '.$children['icon'].'"></i>
        <p>
          '.$children['title'].'
          <i class="fas fa-angle-left right"></i>
        </p>
      </a>';
    }
    
    $menu .= '</li>';
  } else {
    $menu .= '<li class="nav-item">
      <a href="'.$sidebar['link'].'" class="nav-link">
        <i class="nav-icon '.$sidebar['icon'].'"></i>
        <p>
          '.$sidebar['title'].'
        </p>
      </a>
    </li>';
  }

  return $menu;
}


if(!function_exists('toJson')) {
  function toJson($data) {
    header('Content-Type: application/json');
    echo json_encode($data);
  }
}


if(!function_exists('inputPost')) {
  function inputPost($data = null) {
    $input = json_decode(file_get_contents('php://input'), true);
    return $data != null ? isset($input{$data}) ? $input{$data} : '' : $input;
  }
}

function currency($value)
{
    if (is_decimal($value)) {
        return 'Rp. ' . str_replace(",",".", number_format($value, 2)).',-';
    }
    return 'Rp. ' . str_replace(",",".", number_format($value, 0)).',-';
}

function is_decimal( $val )
{
    return is_numeric( $val ) && floor( $val ) != $val;
}