<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Frontend_Controller.php';

class Rajaongkirapi extends Frontend_Controller{
  
  public function __construct()
  {
    parent::__construct();
    $this->load->library('rajaongkir');
    $this->load->driver('cache');
    validate_self_request();
  }
  
  public function waybill($waybill_number = null, $courier = null)
  {
    if (!$waybill = $this->cache->file->get('waybill'))
    {
      $waybill = $this->rajaongkir->waybill($waybill_number, $courier);

      // Save into the cache for 5 minutes
      $this->cache->file->save('waybill', $waybill, 30);
    }

    return toJson([
      'success' => true,
      'data' => json_decode($waybill, TRUE)
    ]);
  }

  public function province()
  {
    if (!$provinces = $this->cache->file->get('provinces'))
    {
      $provinces = $this->rajaongkir->province();

      // Save into the cache for 5 minutes
      $this->cache->file->save('provinces', $provinces, 30000);
    }

    return toJson([
      'success' => true,
      'data' => json_decode($provinces, TRUE)
    ]);
  }

  public function city_sync($province)
  {
    $provinces = json_decode($this->rajaongkir->city($province, null), TRUE);
    
    $array = [];

    foreach($provinces['rajaongkir']['results'] as $province) {
      $array[] = [
        'province_id' => $province['province_id'],
        'city_id' => $province['city_id'],
        'type' => $province['type'],
        'city_name' => $province['city_name'],
        'postal_code' => $province['postal_code']
      ];
    }

    $this->db->insert_batch('cities', $array);
  }

  public function subdistrict_sync($city)
  {
    $provinces = json_decode($this->rajaongkir->district($city), TRUE);
    
    $array = [];

    foreach($provinces['rajaongkir']['results'] as $province) {
      $array[] = [
        'province_id' => $province['province_id'],
        'city_id' => $province['city_id'],
        'type' => $province['type'],
        'city_name' => $province['city_name'],
        'postal_code' => $province['postal_code']
      ];
    }

    $this->db->insert_batch('subdistricts', $array);
  }

  public function city($province = null, $city_id = null)
  {
    if (!$provinces = $this->cache->file->get("{$province}_{$city_id}_provinces"))
    {
      $provinces = $this->rajaongkir->city($province, $city_id);

      // Save into the cache for 5 minutes
      $this->cache->file->save("{$province}_{$city_id}_provinces", $provinces, 30000);
    }

    return toJson([
      'success' => true,
      'data' => json_decode($provinces, TRUE)
    ]);
  }

  public function district( $city_id = null)
  {
    if (!$provinces = $this->cache->file->get("district_{$city_id}_provinces"))
    {
      $provinces = $this->rajaongkir->district($city_id);

      // Save into the cache for 5 minutes
      $this->cache->file->save("district_{$city_id}_provinces", $provinces, 30000);
    }

    return toJson([
      'success' => true,
      'data' => json_decode($provinces, TRUE)
    ]);
  }

  public function cost($from = null, $to = null, $weight = 0, $courier = null)
  {
    $provinces = $this->rajaongkir->cost($from, $to, $weight, $courier);

    return toJson([
      'success' => true,
      'data' => json_decode($provinces, TRUE)
    ]);
  }

  public function costs($from = null, $to = null, $weight = null, $originType = 'city' , $destinationType = 'city')
  {
    $couriers = isset($this->data['setting_website_shipping_courier']) ? explode(",", $this->data['setting_website_shipping_courier']) : ['jne', 'tiki', 'pos'];
    $costs = [];

    $this->load->library('cart');

    $originType = 'subdistrict';
    $from = $this->data['setting_sender_district'];

    $weight = 0;
    foreach($this->cart->contents() as $key => $item) {
      $weight = (int) $weight + ((int) $item['weight'] * $item['qty']);
    }

    if($weight > 30000000) {
      return toJson([
        'success' => true,
        'data' => []
      ]);
    }

    foreach($couriers as $courier) {
      $response = json_decode($this->rajaongkir->cost($from, $to, $weight, $courier, $originType, $destinationType), TRUE);

      foreach($response['rajaongkir']['results'] as $result) {
        foreach($result['costs'] as $cost) {
          $costs[] = [
            'service' => $cost['service'],
            'description' => $cost['description'],
            'code' => $result['code'],
            'code_display' => strtoupper($result['code']),
            'name' => $result['name'],
            'image' => image_courier($result['code']),
            'label' => "{$result['name']} - {$cost['description']} ({$cost['cost'][0]['etd']})",
            'cost' => [
              'value' => $cost['cost'][0]['value'],
              'value_format' => currency($cost['cost'][0]['value']),
              'etd' => $cost['cost'][0]['etd'],
              'note' => $cost['cost'][0]['note']
            ]
          ];
        }
      }
    }

    return toJson([
      'success' => true,
      'data' => $costs ?? []
    ]);
  }
}