<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Frontend_Controller.php';

class Product extends Frontend_Controller{
    function __construct()
    {
        parent::__construct();
        $this->load->model('Product_model');
    } 

    public function all()
    {
        $currentPage = $this->input->get('page') ?? 1;

        $page = $currentPage == 1 ? 0 : (int) $this->input->get('page') - 1;

        return toJson($this->Product_model->pagination(
            $this->input->get('per_page') ?? 10,
            $page,
            base_url('product/all')
        ));
    }

    function read()
    {
        try {
            $data = null;
            
            if($slug = $this->input->get('slug')) {
                $data = $this->Product_model->findBySlug($slug);
            }

            return toJson([
                'success' => true,
                'data' => $data
            ]);
        } catch (Exception $e) {
            return toJson([
                'success' => false,
                'data' => null
            ]);
        }
    }

    function total()
    {
        try {
            return toJson([
                'success' => true,
                'data' => $this->Product_model->countTotal()
            ]);
        } catch (Exception $e) {
            return toJson([
                'success' => false,
                'data' => null
            ]);
        }
    }


    /*
     * Listing of products
     */
    function index()
    {
        try {
            return toJson([
                'success' => true,
                'data' => $this->Product_model->get_all_products()
            ]);
        } catch (Exception $e) {
            return toJson([
                'success' => false,
                'data' => null
            ]);
        }
    }

    /*
     * Adding a new product
     */
    function add()
    {   
        $this->load->library('form_validation');

		$this->form_validation->set_rules('price','Price','required');
		$this->form_validation->set_rules('title','Title','required');
		$this->form_validation->set_rules('category_id','Category Id','required');
		
		if($this->form_validation->run())     
        {   
            $params = array(
				'category_id' => $this->input->post('category_id'),
				'slug' => url_title($this->input->post('title'), "-", TRUE),
				'title' => $this->input->post('title'),
				'video' => $this->input->post('video'),
				'weight' => $this->input->post('weight'),
				'long' => $this->input->post('long'),
				'width' => $this->input->post('width'),
				'height' => $this->input->post('height'),
				'price' => $this->input->post('price'),
                'view' => 0,
                'stock' => $this->input->post('stock'),
				'created_at' => date('Y-m-d H:i:s'),
				'updated_at' => date('Y-m-d H:i:s'),
				'description' => $this->input->post('description'),
            );

            if(!empty($_FILES["image"]["name"])) {
                $params['image'] = $this->_uploadImage();
              }
            
            $product_id = $this->Product_model->add_product($params);
            return toJson([
                'success' => true,
                'data' => null
            ]);
        }
        else
        {
			return toJson([
                'success' => false,
                'data' => null
            ]);
        }
    }  

    /*
     * Editing a product
     */
    function edit()
    {   
        // check if the product exists before trying to edit it
        $id = $this->input->post('id') ?? 0;
        $data['product'] = $this->Product_model->get_product($id);
        
        if(isset($data['product']['id']))
        { 
            $read = $this->Product_model->findById($id);
            
            $params = array(
                'category_id' => $this->input->post('category_id') ?? $read->category_id,
                'title' => $this->input->post('title') ?? $read->title,
                'slug' => url_title($this->input->post('title'), "-", TRUE) ?? $read->slug,
                'video' => $this->input->post('video') ?? $read->video,
                'weight' => $this->input->post('weight') ?? $read->weight,
                'long' => $this->input->post('long') ?? $read->long,
                'width' => $this->input->post('width') ?? $read->width,
                'height' => $this->input->post('height') ?? $read->height,
                'price' => $this->input->post('price') ?? $read->price,
                'view' => $this->input->post('view') ?? $read->view,
                'stock' => $this->input->post('stock') ?? $read->stock,
                'updated_at' => date('Y-m-d H:i:s'),
                'description' => $this->input->post('description') ?? $read->description,
            );

            if(!empty($_FILES["image"]["name"])) {
                $params['image'] = $this->_uploadImage();
            } else {
                $params['image'] = $read->image;
            }

            $this->Product_model->update_product($id,$params);            
            return toJson([
                'success' => true,
                'data' => null
            ]);
        }
        else
            return toJson([
                'success' => false,
                'data' => $data['product']
            ]);
    } 

    /*
     * Deleting product
     */
    function remove($id)
    {
        $product = $this->Product_model->get_product($id);

        // check if the product exists before trying to delete it
        if(isset($product['id']))
        {
            $this->Product_model->delete_product($id);
            return toJson([
                'success' => true,
                'data' => null
            ]);
        }
        else
            return toJson([
                'success' => false,
                'data' => null
            ]);
    }

    private function _uploadImage()
    {
        $config['upload_path']          = './uploads/images/';
        $config['allowed_types']        = 'gif|jpg|png|jpeg';
        $config['file_name']            = date('Yhis') . '_' . time() . '-' . md5(time());
        $config['overwrite']			      = false;
        $config['max_size']             = 10240; // 1MB

        $this->load->library('upload', $config);

        if ($this->upload->do_upload('image')) {
            return $this->upload->data("file_name");
        }
        
        return null;
    }
    
}
