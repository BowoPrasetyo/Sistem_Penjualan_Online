<?php

/**
 * RajaOngkir CodeIgniter Library
 * Digunakan untuk mengkonsumsi API RajaOngkir dengan mudah
 * 
 * @author Damar Riyadi <damar@tahutek.net>
 */
defined('BASEPATH') OR exit('No direct script access allowed');
require_once 'RajaOngkir/endpoints.php';

class RajaOngkir extends Endpoints {

    private $api_key;
    private $account_type;

    public function __construct() {
        // Pastikan bahwa PHP mendukung cURL
        if (!function_exists('curl_init')) {
            log_message('error', 'cURL Class - PHP was not built with cURL enabled. Rebuild PHP with --with-curl to use cURL.');
        }
        $this->_ci = & get_instance();
        $this->_ci->load->config('rajaongkir', TRUE);
        $this->_ci->load->model('Setting_model');
        // Pastikan Anda sudah memasukkan API Key di application/config/rajaongkir.php
        // if ($this->_ci->config->item('rajaongkir_api_key', 'rajaongkir') == "") {
        //     log_message("error", "Harap masukkan API KEY Anda di config.");
        // } else {
        //     $this->api_key = $this->_ci->config->item('rajaongkir_api_key', 'rajaongkir');
        //     $this->account_type = $this->_ci->config->item('rajaongkir_account_type', 'rajaongkir');
        // }
        
        $rajaongkir_api_key = $this->_ci->Setting_model->get_setting_by_name('rajaongkir_api_key')['value'] ?? '';
        $rajaongkir_account_type = $this->_ci->Setting_model->get_setting_by_name('rajaongkir_account_type')['value'] ?? '';

        if ($rajaongkir_api_key == "" || $rajaongkir_account_type == "") {
            log_message("error", "Harap setting API KEY dan Tipe Akun.");
        } else {
            $this->api_key = $rajaongkir_api_key;
            $this->account_type = $rajaongkir_account_type;
        }
        parent::__construct($this->api_key, $this->account_type);
    }
}
