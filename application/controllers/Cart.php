<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Frontend_Controller.php';

class Cart extends Frontend_Controller{
  function __construct()
  {
    parent::__construct();
    $this->load->library('cart');
    $this->load->model('Product_model');
  }

  public function add()
  {
    try {
      $id = $this->input->post('id') ?? 1;
      $qty = $this->input->post('qty') ?? 1;
      $slug = $this->input->post('slug');
      $stock = $this->input->post('stock');

      if($id == '' || !$id || $qty == '' || !$qty) {
        return toJson([
          'success' => false,
          'description' => 'alert',
          'message' => 'ID cant be null'
        ]);
      }

      if(!$this->data['is_login']) {
        return toJson([
          'success' => false,
          'description' => 'login',
          'message' => 'Gagal tambah keranjang'
        ]);
      }

      $product = $this->Product_model->findById($id);

      if((int) $qty > (int) $product->stock) {
        return toJson([
          'success' => false,
          'description' => 'alert',
          'message' => 'Gagal, stok kurang.'
        ]);
      }

      $data = array(
        'id'      => $product->id,
        'qty'     => $qty,
        'price'   => $product->price,
        'name'    => $product->title,
        'slug'    => $product->slug,
        'image'    => $this->input->post('image') ?? null,
        'weight' => $product->weight,
        'stock'    => $product->stock,
        'note' => ''
      );

      $insert = $this->cart->insert($data);

      //set ke stock jika melebihi
      $cart = $this->cart->contents()[$insert];

      if((int) $cart['qty'] > (int) $product->stock) {
        $this->cart->update([
          'rowid' => $insert,
          'qty' => $product->stock,
        ]);

        return toJson([
          'success' => false,
          'description' => 'alert',
          'message' => 'Gagal, stok kurang.'
        ]);
      }

      if(!$insert) {
        return toJson([
          'success' => false,
          'description' => 'alert',
          'message' => 'Gagal tambah keranjang'
        ]);
      }

      return toJson([
        'success' => true,
        'description' => 'alert',
        'message' => 'Sukses tambah keranjang'
      ]);
    } catch(Exception $e) {
      return toJson([
        'success' => false,
        'description' => 'alert',
        'message' => 'Gagal tambah keranjang'
      ]);
    }
  }

  public function delete_cart()
  {
    try {
      $rowid = $this->input->post('rowid');

      $this->cart->update([
        'rowid' => $rowid,
        'qty' => 0
      ]);

      return toJson([
        'success' => true,
        'description' => 'alert',
        'message' => 'Berhasil Delete Cart'
      ]);
    } catch (Exception $e) {
      return toJson([
        'success' => false,
        'description' => 'alert',
        'message' => 'Gagal Update Cart'
      ]);
    }
  }

  public function update_qty()
  {
    try {
      $rowid = $this->input->post('rowid');
      $qty = $this->input->post('qty');

      $this->cart->update([
        'rowid' => $rowid,
        'qty' => $qty
      ]);

      return toJson([
        'success' => true,
        'description' => 'alert',
        'message' => 'Berhasil Update Qty'
      ]);
    } catch (Exception $e) {
      return toJson([
        'success' => false,
        'description' => 'alert',
        'message' => 'Gagal Update Qty'
      ]);
    }
  }

  public function update_note()
  {
    try {
      $rowid = $this->input->post('rowid');
      $note = $this->input->post('note');

      $this->cart->update([
        'rowid' => $rowid,
        'note' => $note,
      ]);

      return toJson([
        'success' => true,
        'description' => 'alert',
        'message' => 'Berhasil update Catatan'
      ]);
    } catch(Exception $e) {
      return toJson([
        'success' => false,
        'description' => 'alert',
        'message' => 'Gagal Update Catatan'
      ]);
    }
  }

  public function lists()
  {
    try {
      $contents = $this->cart->contents();

      return toJson([
        'success' => true,
        'description' => 'alert',
        'message' => 'Sukses ambil data',
        'data' => $contents
      ]);
    } catch (Exception $e) {
      return toJson([
        'success' => false,
        'description' => 'alert',
        'message' => 'Gagal ambil data',
        'data' => null
      ]);
    }
  }
}
