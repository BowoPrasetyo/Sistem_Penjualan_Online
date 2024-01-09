<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Frontend_Controller.php';

class Category extends Frontend_Controller{
    function __construct()
    {
        parent::__construct();
        $this->load->model('Category_model');
    } 

    public function all()
    {
        $currentPage = $this->input->get('page') ?? 1;

        $page = $currentPage == 1 ? 0 : (int) $this->input->get('page') - 1;

        return toJson($this->Category_model->pagination(
            $this->input->get('per_page') ?? 10,
            $page,
            base_url('category/all')
        ));
    }

    /*
     * Listing of categories
     */
    function index()
    {
        $data['categories'] = $this->Category_model->get_all_categories();
        
        return toJson([
            'success' => true,
            'data' => $data['categories']
        ]);
    }

    /*
     * Adding a new category
     */
    function add()
    {   
        $this->load->library('form_validation');

		$this->form_validation->set_rules('name','Name','required');
		
		if($this->form_validation->run())     
        {   
            $params = array(
				'name' => $this->input->post('name'),
				'created_at' => $this->input->post('created_at'),
				'updated_at' => $this->input->post('updated_at'),
				'description' => $this->input->post('description'),
            );
            
            $category_id = $this->Category_model->add_category($params);
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
     * Editing a category
     */
    function edit()
    {   
        $id = $this->input->post('id') ?? 0;
        // check if the category exists before trying to edit it
        $data['category'] = $this->Category_model->get_category($id);
        
        if(isset($data['category']['id']))
        {
            $this->load->library('form_validation');

			$this->form_validation->set_rules('name','Name','required');
		
			if($this->form_validation->run())     
            {   
                $params = array(
					'name' => $this->input->post('name'),
					'created_at' => $this->input->post('created_at'),
					'updated_at' => $this->input->post('updated_at'),
					'description' => $this->input->post('description'),
                );

                $this->Category_model->update_category($id,$params);            
                return toJson([
                    'success' => true,
                    'data' => null
                ]);
            }
            else
            {
                $data['_view'] = 'category/edit';
                return toJson([
                    'success' => false,
                    'data' => null
                ]);
            }
        }
        else
            return toJson([
                'success' => false,
                'data' => null
            ]);
    } 

    /*
     * Deleting category
     */
    function remove($id)
    {
        $category = $this->Category_model->get_category($id);

        // check if the category exists before trying to delete it
        if(isset($category['id']))
        {
            $this->Category_model->delete_category($id);
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
    
}
