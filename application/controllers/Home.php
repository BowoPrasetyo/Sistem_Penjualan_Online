<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Frontend_Controller.php';

class Home extends Frontend_Controller {
  public function __construct()
  {
    parent::__construct();
    $this->load->model('Product_model');
    $this->load->model('Category_model');
    $this->load->model('Product_image_model');
    $this->load->model('Product_discussion_model');
    $this->load->model('Transaction_model');
    $this->load->model('Transaction_detail_model');
    $this->load->model('Transaction_shipping_model');
    $this->load->model('User_model');
    $this->load->model('Commision_model');

    // if($referral = $this->input->get('reff')) {
    //   $checkAffiliate = $this->User_model->findByReferral($referral);
    //   if($checkAffiliate) {
    //     // jika aff data sebelumnya masih valid
    //     if(!get_cookie('aff_data')) {
    //       set_cookie('aff_data', $checkAffiliate['id'], 86400 * 30);
    //     }
    //   }
    // }
  }
	public function index()
	{
    $this->data['page'] = 'frontend/v_home';
    
    if (!$this->data['products'] = $this->cache->file->get('products_home')){
      $this->data['products'] = $this->Product_model->get_all_valid_products();

      $this->cache->file->save('products_home', $this->data['products'], 60);
    }

    if (!$this->data['categories'] = $this->cache->file->get('categories_home')){
      $this->data['categories'] = $this->Category_model->get_all_categories_publish();

      $this->cache->file->save('categories_home', $this->data['categories'], 60);
    }

		$this->load->view('frontend/index', $this->data);
  }
  
  public function search()
	{
    $this->data['page'] = 'frontend/v_search';

    $this->data['products'] = $this->Product_model->get_search_valid_products(
      htmlspecialchars(html_escape($this->input->get('q', TRUE))) ?? null,
      htmlspecialchars(html_escape($this->input->get('c', TRUE))) ?? null
    );

    $this->data['categories'] = $this->Category_model->get_all_categories_with_count();
		$this->load->view('frontend/index', $this->data);
  }

  public function referral($referral)
  {
    $checkAffiliate = $this->User_model->findByReferral($referral);
    if($checkAffiliate) {
      // jika aff data sebelumnya masih valid
      if(!get_cookie('aff_data')) {
        set_cookie('aff_data', $checkAffiliate['id'], 86400 * 30);
      }
    }

    redirect(base_url());
  }

  public function get_discussions($product = 0, $parent = 0)
  {
    $discussions = [];
    
    $data = $this->Product_discussion_model->get_all_product_discussions([
      'product_id' => $product,
      'parent_id' => $parent
    ]);

    foreach($data as $key => $discussion) {
      $discussions[] = [
        'id' => $discussion['id'],
        'user_id' => $discussion['user_id'],
        'content' => $discussion['content'],
        'childrens' => $this->get_discussions($product, $discussion['id']),
        'created_at' => $discussion['created_at']
      ];
    }

    return $discussions;
  }

  public function add_discussion()
  {
    $this->load->library('user_agent');

    $add = $this->Product_discussion_model->add_product_discussion([
      'user_id' => 1,
      'parent_id' => $this->input->post('parent') ?? 0,
      'product_id' => $this->input->post('product_id'),
      'content' => $this->input->post('content', TRUE) ?? '',
      'created_at' => date('Y-m-d H:i:s'),
      'updated_at' => date('Y-m-d H:i:s'),
    ]);

    if($add) {
      $this->session->set_flashdata('success', 'Berhasil Diskusi');
      return redirect($this->agent->referrer());
    }

    $this->session->set_flashdata('err', 'Gagal Diskusi');
    return $this->agent->referrer();
  }
  
  public function product_detail($slug = '')
	{
    $affiliate = $this->input->get('aff') ?? 0;
    $this->data['page'] = 'frontend/v_product_detail';
    $this->data['product'] = $this->Product_model->findBySlug($slug) ?? null;
    $this->data['discussions'] = $this->get_discussions($this->data['product']->id ?? 0);
    $checkAffiliate = $this->User_model->get_user($affiliate);
    if($checkAffiliate) {
      // jika aff data sebelumnya masih valid
      if(!get_cookie('aff_data')) {
        set_cookie('aff_data', $checkAffiliate['id'], 86400 * 30);
      }
    }

    if($this->data['product'] != null) {
      $this->data['product_images'] = $this->Product_image_model->find_by_product($this->data['product']->product_ref);
      $this->data['page_title'] = $this->data['product']->title;
    } else {
      return redirect(base_url());
    }

		$this->load->view('frontend/index', $this->data);
  }
  
  public function cart()
	{
    $this->load->library('cart');

    $this->data['page'] = 'frontend/v_cart';
		$this->load->view('frontend/index', $this->data);
  }

  public function checkout()
	{
    $this->load->library('cart');

    if(count($this->cart->contents()) <= 0) {
      return redirect(base_url());
    }
    
    $this->data['page'] = 'frontend/v_checkout';
    $this->data['weight'] = 0;

    foreach($this->cart->contents() as $key => $item) {
      $this->data['weight'] = (int) $this->data['weight'] + ((int) $item['weight'] * $item['qty']);
    }

		$this->load->view('frontend/index', $this->data);
  }  
}
