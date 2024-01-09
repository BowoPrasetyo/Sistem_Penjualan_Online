<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Frontend_Controller.php';

class Product_discussion extends Frontend_Controller{
    function __construct()
    {
        parent::__construct();
        $this->load->model('Product_discussion_model');
    } 

    /*
     * Listing of product_discussions
     */
    function index()
    {
        $data['product_discussions'] = $this->Product_discussion_model->get_all_product_discussions();
        
        $data['_view'] = 'product_discussion/index';
        $this->load->view('layouts/main',$data);
    }

    /*
     * Adding a new product_discussion
     */
    function add()
    {   
        $this->load->library('form_validation');

		$this->form_validation->set_rules('user_id','User Id','required');
		$this->form_validation->set_rules('product_id','Product Id','required');
		
		if($this->form_validation->run())     
        {   
            $params = array(
				'user_id' => $this->input->post('user_id'),
				'product_id' => $this->input->post('product_id'),
				'created_at' => $this->input->post('created_at'),
				'updated_at' => $this->input->post('updated_at'),
				'content' => $this->input->post('content'),
            );
            
            $product_discussion_id = $this->Product_discussion_model->add_product_discussion($params);
            redirect('product_discussion/index');
        }
        else
        {
			$this->load->model('User_model');
			$data['all_users'] = $this->User_model->get_all_users();

			$this->load->model('Product_model');
			$data['all_products'] = $this->Product_model->get_all_products();
            
            $data['_view'] = 'product_discussion/add';
            $this->load->view('layouts/main',$data);
        }
    }  

    /*
     * Editing a product_discussion
     */
    function edit($id)
    {   
        // check if the product_discussion exists before trying to edit it
        $data['product_discussion'] = $this->Product_discussion_model->get_product_discussion($id);
        
        if(isset($data['product_discussion']['id']))
        {
            $this->load->library('form_validation');

			$this->form_validation->set_rules('user_id','User Id','required');
			$this->form_validation->set_rules('product_id','Product Id','required');
		
			if($this->form_validation->run())     
            {   
                $params = array(
					'user_id' => $this->input->post('user_id'),
					'product_id' => $this->input->post('product_id'),
					'created_at' => $this->input->post('created_at'),
					'updated_at' => $this->input->post('updated_at'),
					'content' => $this->input->post('content'),
                );

                $this->Product_discussion_model->update_product_discussion($id,$params);            
                redirect('product_discussion/index');
            }
            else
            {
				$this->load->model('User_model');
				$data['all_users'] = $this->User_model->get_all_users();

				$this->load->model('Product_model');
				$data['all_products'] = $this->Product_model->get_all_products();

                $data['_view'] = 'product_discussion/edit';
                $this->load->view('layouts/main',$data);
            }
        }
        else
            show_error('The product_discussion you are trying to edit does not exist.');
    } 

    /*
     * Deleting product_discussion
     */
    function remove($id)
    {
        $product_discussion = $this->Product_discussion_model->get_product_discussion($id);

        // check if the product_discussion exists before trying to delete it
        if(isset($product_discussion['id']))
        {
            $this->Product_discussion_model->delete_product_discussion($id);
            redirect('product_discussion/index');
        }
        else
            show_error('The product_discussion you are trying to delete does not exist.');
    }
    
}
