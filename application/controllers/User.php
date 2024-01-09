<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Frontend_Controller.php';

class User extends Frontend_Controller{
    function __construct()
    {
        parent::__construct();
        $this->load->model('User_model');
    } 

    public function affiliators()
    {
        header('Content-Type: application/json');
        echo $this->User_model->affiliators(
            $this->session->userdata('user')->id
        );
    }

    public function all()
    {
        $currentPage = $this->input->get('page') ?? 1;

        $page = $currentPage == 1 ? 0 : (int) $this->input->get('page') - 1;

        return toJson($this->User_model->paginationMember(
            $this->input->get('per_page') ?? 10,
            $page,
            base_url('user/all')
        ));
    }

    /*
     * Listing of users
     */
    function index()
    {
        $data['users'] = $this->User_model->get_all_users();
        
        $data['_view'] = 'user/index';
        $this->load->view('layouts/main',$data);
    }

    /*
     * Adding a new user
     */
    function add()
    {   
        if(isset($_POST) && count($_POST) > 0)     
        {   
            $params = array(
				'password' => $this->input->post('password'),
				'updated_at' => $this->input->post('updated_at'),
				'first_name' => $this->input->post('first_name'),
				'last_name' => $this->input->post('last_name'),
				'email' => $this->input->post('email'),
				'token' => $this->input->post('token'),
				'token_expired' => $this->input->post('token_expired'),
				'created_at' => $this->input->post('created_at'),
            );
            
            $user_id = $this->User_model->add_user($params);
            redirect('user/index');
        }
        else
        {            
            $data['_view'] = 'user/add';
            $this->load->view('layouts/main',$data);
        }
    }  

    /*
     * Editing a user
     */
    function edit($id)
    {   
        // check if the user exists before trying to edit it
        $data['user'] = $this->User_model->get_user($id);
        
        if(isset($data['user']['id']))
        {
            if(isset($_POST) && count($_POST) > 0)     
            {   
                $params = array(
					'password' => $this->input->post('password'),
					'updated_at' => $this->input->post('updated_at'),
					'first_name' => $this->input->post('first_name'),
					'last_name' => $this->input->post('last_name'),
					'email' => $this->input->post('email'),
					'token' => $this->input->post('token'),
					'token_expired' => $this->input->post('token_expired'),
					'created_at' => $this->input->post('created_at'),
                );

                $this->User_model->update_user($id,$params);            
                redirect('user/index');
            }
            else
            {
                $data['_view'] = 'user/edit';
                $this->load->view('layouts/main',$data);
            }
        }
        else
            show_error('The user you are trying to edit does not exist.');
    } 

    /*
     * Deleting user
     */
    function remove($id)
    {
        $user = $this->User_model->get_user($id);

        // check if the user exists before trying to delete it
        if(isset($user['id']))
        {
            $this->User_model->delete_user($id);
            redirect('user/index');
        }
        else
            show_error('The user you are trying to delete does not exist.');
    }
    
}
