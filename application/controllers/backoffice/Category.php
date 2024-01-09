<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Backoffice_Controller.php';

class Category extends Backoffice_Controller {
  public function __construct()
  {
    parent::__construct();
    $this->load->model('Product_model');
    $this->load->model('Category_model');
  }

	public function index()
	{
    $this->data['page_title'] = 'Kategori';
    $this->data['page'] = 'backoffice/category/index';

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Kategori',
        'link' => 1
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function create()
	{
    $this->data['page_title'] = 'Tambah Kategori';
    $this->data['page'] = 'backoffice/category/create';
    $this->data['edit'] = null;

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Kategori',
        'link' => '#'
      ],
      [
        'title' => 'Tambah Kategori',
        'link' => 1
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function edit($id)
	{
    $this->data['page_title'] = 'Edit Kategori';
    $this->data['page'] = 'backoffice/category/create';
    $this->data['edit'] = $this->Category_model->get_category($id) ?? null;

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Kategori',
        'link' => '#'
      ],
      [
        'title' => $this->data['edit']['name'],
        'link' => '#'
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function store()
  {
    try {
      $this->load->library('form_validation');

      $this->form_validation->set_rules('name','Name','required');
      
      if($this->form_validation->run()) {   
        $params = array(
          'name' => $this->input->post('name'),
          'status' => $this->input->post('status'),
          'created_at' => $this->input->post('created_at'),
          'updated_at' => $this->input->post('updated_at'),
          'description' => $this->input->post('description'),
        );
              
        $product_id = $this->Category_model->add_category($params);
        $this->session->set_flashdata('success', 'Berhasil menambah Kategori');
        return redirect(base_url('backoffice/category/edit/' . $product_id));
      } else {
        $this->session->set_flashdata('err', 'Gagal menambah Kategori');
        return redirect(base_url('backoffice/category'));
      }
    } catch (Exception $e) {
      $this->session->set_flashdata('err', 'Sistem sedang gangguan');
      return redirect(base_url('backoffice/category'));
    }
  }

  public function update($id = 0)
  {
    try {
      $this->load->library('form_validation');

      $this->form_validation->set_rules('name','Name','required');
      
      if($this->form_validation->run()) {   
        $params = array(
          'name' => $this->input->post('name'),
          'status' => $this->input->post('status'),
          'created_at' => $this->input->post('created_at'),
          'updated_at' => $this->input->post('updated_at'),
          'description' => $this->input->post('description'),
        );
              
        $product_id = $this->Category_model->update_category($id, $params);
        $this->session->set_flashdata('success', 'Berhasil mengubah Kategori');
        return redirect(base_url('backoffice/category/edit/' . $id));
      } else {
        $this->session->set_flashdata('err', 'Gagal mengubah Kategori');
        return redirect(base_url('backoffice/category/edit/' . $id));
      }
    } catch (Exception $e) {
      $this->session->set_flashdata('err', 'Sistem sedang gangguan');
      return redirect(base_url('backoffice/category/edit/' . $id));
    }
  }

  public function dataList()
  {
    header('Content-Type: application/json');
    echo $this->Category_model->datatable();
  }
}