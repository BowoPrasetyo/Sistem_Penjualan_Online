<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Backoffice_Controller.php';

class Product extends Backoffice_Controller {
  public function __construct()
  {
    parent::__construct();
    $this->load->model('Product_model');
    $this->load->model('Category_model');
  }

	public function index()
	{
    $this->data['page_title'] = 'Product';
    $this->data['page'] = 'backoffice/product/index';

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Produk',
        'link' => 1
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function create()
	{
    $this->data['page_title'] = 'Tambah Produk';
    $this->data['page'] = 'backoffice/product/create';
    $this->data['categories'] = $this->Category_model->get_all_categories();
    $this->data['edit'] = null;

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Produk',
        'link' => '#'
      ],
      [
        'title' => 'Tambah Produk',
        'link' => 1
      ]
    ];

    $product_id = $this->Product_model->add_product([
      'category_id' => 1,
      'title' => 'Untitled ' . time(),
      'product_ref' => rand(1000, 9000) . time(),
      'created_at' => date('Y-m-d H:i:s'),
      'view' => 0,
      'status' => 'draft'
    ]);

    $this->session->set_flashdata('success', 'Berhasil membuat Draft Produk');
    return redirect(base_url('backoffice/product/edit/' . $product_id));

		$this->load->view('backoffice/index', $this->data);
  }

  public function edit($id)
	{
    $this->data['page_title'] = 'Edit Produk';
    $this->data['page'] = 'backoffice/product/create';
    $this->data['categories'] = $this->Category_model->get_all_categories();
    $this->data['edit'] = $this->Product_model->get_product($id) ?? null;

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Produk',
        'link' => '#'
      ],
      [
        'title' => $this->data['edit']['title'],
        'link' => '#'
      ]
    ];

    if($this->data['edit']['product_ref'] == null || $this->data['edit']['product_ref'] == '') {
      $this->data['edit']['product_ref'] = rand(1000, 9000) . time();
    }

		$this->load->view('backoffice/index', $this->data);
  }

  public function store()
  {
    try {
      $this->load->library('form_validation');

      $this->form_validation->set_rules('price','Price','required');
      $this->form_validation->set_rules('title','Title','required');
      $this->form_validation->set_rules('category_id','Category Id','required');
      
      if($this->form_validation->run()) {   
        $params = array(
          'category_id' => $this->input->post('category_id'),
          'slug' => $this->input->post('slug') ?? url_title($this->input->post('title'), "-", TRUE) . '-' . rand(1000, 9000),
          'title' => $this->input->post('title'),
          'status' => $this->input->post('status'),
          'product_ref' => $this->input->post('product_ref'),
          'video' => $this->input->post('video'),
          'weight' => $this->input->post('weight'),
          'long' => $this->input->post('long'),
          'width' => $this->input->post('width'),
          'height' => $this->input->post('height'),
          'price' => $this->input->post('price'),
          'commision_maintenance' => $this->input->post('commision_maintenance'),
          'commision_affiliator' => $this->input->post('commision_affiliator'),
          'commision_provider' => $this->input->post('commision_provider'),
	        'commision_mediator' => $this->input->post('commision_mediator'),
	        'commision_leader' => $this->input->post('commision_leader'),
	        'commision_cs' => $this->input->post('commision_cs'),
          'view' => 0,
          'stock' => $this->input->post('stock'),
          'created_at' => date('Y-m-d H:i:s'),
          'updated_at' => date('Y-m-d H:i:s'),
          'description' => $this->input->post('description'),
        );
              
        $product_id = $this->Product_model->add_product($params);
        $this->session->set_flashdata('success', 'Berhasil menambah produk');
        return redirect(base_url('backoffice/product/edit/' . $product_id));
      } else {
        $this->session->set_flashdata('err', 'Gagal menambah produk');
        return redirect(base_url('backoffice/product'));
      }
    } catch (Exception $e) {
      $this->session->set_flashdata('err', 'Sistem sedang gangguan');
      return redirect(base_url('backoffice/product'));
    }
  }

  public function update($id = 0)
  {
    try {
      $this->load->library('form_validation');

      $this->form_validation->set_rules('price','Price','required');
      $this->form_validation->set_rules('title','Title','required');
      $this->form_validation->set_rules('category_id','Category Id','required');
      
      if($this->form_validation->run()) {   
        $params = array(
          'category_id' => $this->input->post('category_id'),
          'slug' => $this->input->post('slug') ?? url_title($this->input->post('title'), "-", TRUE) . '-' . rand(1000, 9000),
          'title' => $this->input->post('title'),
          'status' => $this->input->post('status'),
          'product_ref' => $this->input->post('product_ref'),
          'video' => $this->input->post('video'),
          'weight' => $this->input->post('weight'),
          'long' => $this->input->post('long'),
          'width' => $this->input->post('width'),
          'height' => $this->input->post('height'),
          'price' => $this->input->post('price'),
          'commision_maintenance' => $this->input->post('commision_maintenance'),
          'commision_affiliator' => $this->input->post('commision_affiliator'),
          'commision_provider' => $this->input->post('commision_provider'),
	        'commision_mediator' => $this->input->post('commision_mediator'),
	        'commision_leader' => $this->input->post('commision_leader'),
	        'commision_cs' => $this->input->post('commision_cs'),
          'view' => 0,
          'stock' => $this->input->post('stock'),
          'updated_at' => date('Y-m-d H:i:s'),
          'description' => $this->input->post('description'),
        );
              
        $product_id = $this->Product_model->update_product($id, $params);
        $this->session->set_flashdata('success', 'Berhasil mengubah produk');
        return redirect(base_url('backoffice/product/edit/' . $id));
      } else {
        $this->session->set_flashdata('err', 'Gagal mengubah produk');
        return redirect(base_url('backoffice/product/edit/' . $id));
      }
    } catch (Exception $e) {
      $this->session->set_flashdata('err', 'Sistem sedang gangguan');
      return redirect(base_url('backoffice/product/edit/' . $id));
    }
  }

  public function update_ajax($id = 0)
  {
    try {
      $this->load->library('form_validation');

      $this->form_validation->set_rules('price','Price','required');
      $this->form_validation->set_rules('title','Title','required');
      $this->form_validation->set_rules('category_id','Category Id','required');
      
      if($this->form_validation->run()) {   
        $params = array(
          'category_id' => $this->input->post('category_id'),
          'slug' => $this->input->post('slug')  ?? url_title($this->input->post('title'), "-", TRUE) . '-' . rand(1000, 9000),
          'title' => $this->input->post('title'),
          'status' => $this->input->post('status'),
          'product_ref' => $this->input->post('product_ref'),
          'video' => $this->input->post('video'),
          'weight' => $this->input->post('weight'),
          'long' => $this->input->post('long'),
          'width' => $this->input->post('width'),
          'height' => $this->input->post('height'),
          'price' => $this->input->post('price'),
          'commision_maintenance' => $this->input->post('commision_maintenance'),
          'commision_affiliator' => $this->input->post('commision_affiliator'),
          'commision_provider' => $this->input->post('commision_provider'),
	        'commision_mediator' => $this->input->post('commision_mediator'),
	        'commision_leader' => $this->input->post('commision_leader'),
	        'commision_cs' => $this->input->post('commision_cs'),
          'view' => 0,
          'stock' => $this->input->post('stock'),
          'updated_at' => date('Y-m-d H:i:s'),
          'description' => $this->input->post('description'),
        );
              
        $product_id = $this->Product_model->update_product($id, $params);
      } else {
      }
    } catch (Exception $e) {
    }
  }

  public function upload_image()
  {
    $upload = uploadGlobalFile(
      'image',
      'resources/upload/img',
      'product'
    );

    if($upload != null) {
      $isThumnail = 0;

      $checkThumbail = $this->db
        ->where('product_ref', $this->input->post('product_ref'))
        ->where('is_thumbnail', 1)
        ->get('product_images')
        ->num_rows();

      if($checkThumbail <= 0) {
        $isThumnail = 1;
      }

      $this->db->insert('product_images',array(
        'product_ref'=> $this->input->post('product_ref'),
        'image'=> $upload,
        'token' => $this->input->post('token'),
        'type' => $this->input->post('type'),
        'is_thumbnail' => $isThumnail
      ));
    }
  }

  public function set_thumbnail()
  {
    try {
      $product_ref = $this->input->post('product_ref');
      $token = $this->input->post('token');

      $this->db->trans_start();

      $this->db->where([
        'product_ref' => $product_ref,
      ])
      ->set('is_thumbnail', 0)
      ->update('product_images');

      $this->db->where([
        'product_ref' => $product_ref,
        'token' => $token,
      ])
      ->set('is_thumbnail', 1)
      ->update('product_images');

      if ($this->db->trans_status() === FALSE){
        $this->db->trans_rollback();
      }
      else{
        $this->db->trans_commit();
      }

    } catch (Exception $e) {

    }
  }

  public function delete_image()
  {
    try {
      $product_ref = $this->input->post('product_ref');
      $token = $this->input->post('token');

      $this->db->trans_start();

      $row = $this->db->where([
        'product_ref' => $product_ref,
        'token' => $token
      ])
      ->get('product_images')
      ->row();

      $product_image = $row->image;

      $this->db->where([
        'product_ref' => $product_ref,
        'token' => $token,
      ])
      ->delete('product_images');

      if ($this->db->trans_status() === FALSE){
        $this->db->trans_rollback();
      }
      else{
        @unlink('./resources/upload/img/' . $product_image);
        $this->db->trans_commit();
      }

    } catch (Exception $e) {

    }
  }

  public function get_images()
  {
    $product_ref = $this->input->get('product_ref');

    $data = $this->db->where('product_ref', $product_ref)->order_by('is_thumbnail', 'DESC')->get('product_images')->result();

    return toJson([
      'success' => true,
      'data' => $data ?? []
    ]);
  }

  public function dataList()
  {
    header('Content-Type: application/json');
    echo $this->Product_model->datatable();
  }
}
