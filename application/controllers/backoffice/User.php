<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Backoffice_Controller.php';

class User extends Backoffice_Controller {
  public function __construct()
  {
    parent::__construct();
    $this->load->model('User_model');
  }

  public function affiliates()
  {
      header('Content-Type: application/json');
      echo $this->User_model->affiliates();
  }

  public function member_list()
  {
      header('Content-Type: application/json');
      echo $this->User_model->members();
  }

  public function admins()
  {
      header('Content-Type: application/json');
      echo $this->User_model->admins();
  }

  public function leaders()
  {
      header('Content-Type: application/json');
      echo $this->User_model->leaders();
  }

  public function password()
	{
    $this->data['page_title'] = 'Ubah Password';
    $this->data['page'] = 'backoffice/user/password_change';

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Ubah Password',
        'link' => ''
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function update_password()
  {
    try {
      $params = [
        'password_old' => htmlspecialchars($this->input->post('password_old')),
        'password' => htmlspecialchars($this->input->post('password')),
        'password_confirm' => htmlspecialchars($this->input->post('password_confirm')),
      ];

      if($params['password'] != $params['password_confirm']) {
        $this->session->set_flashdata('err', 'Password Tidak Sama');
        return redirect(base_url('backoffice/user/password'));
      }

      $user = $this->User_model->get_user($this->data['admin']->id);

      if(!password_verify($params['password_old'], $user['password'])) {
        $this->session->set_flashdata('err', 'Password Lama Tidak Sama');
        return redirect(base_url('backoffice/user/password'));
      }

      if(password_verify($params['password'], $user['password'])) {
        $this->session->set_flashdata('err', 'Password Tidak Boleh sama dengan sebelumnya');
        return redirect(base_url('backoffice/user/password'));
      }

      $update = $this->User_model->update_user($this->data['admin']->id, [
        'password' => password_hash($params['password'], PASSWORD_BCRYPT)
      ]);

      if(!$update) {
        $this->session->set_flashdata('err', 'Gagal Update Password');
        return redirect(base_url('backoffice/user/password'));
      }

      $this->session->set_flashdata('success', 'Berhasil Update Password');

      return redirect(base_url('backoffice/user/password'));
    } catch (Exception $e) {
      $this->session->set_flashdata('err', 'Sistem sedang gangguan');
      return redirect(base_url('backoffice/user/password'));
    }
  }

	public function admin()
	{
    $this->data['page_title'] = 'Admin';
    $this->data['page'] = 'backoffice/user/admin';

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Admin',
        'link' => ''
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function admin_add()
	{
    $this->data['page_title'] = 'Tambah Admin';
    $this->data['page'] = 'backoffice/user/admin_add';

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Tambah Admin',
        'link' => ''
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function admin_add_post()
  {
    $passwordConfirm = htmlspecialchars($this->input->get('password_confirm', TRUE));
    $password = htmlspecialchars($this->input->get('password', TRUE));

    $params = [
      'first_name' => $this->input->post('first_name', TRUE),
      'last_name' => $this->input->post('last_name', TRUE),
      'email' => $this->input->post('email', TRUE),
      'password' => password_hash($this->input->post('password', TRUE), PASSWORD_BCRYPT),
      'referral' => $this->User_model->generate_referral(),
      'role' => 'admin'
    ];

    $check = $this->User_model->checkUser($params['email']);

    if(
      $params['first_name'] == '' ||
      $params['last_name'] == '' || 
      $params['email'] == '' ||
      $params['password'] == '' ||
      $password != $passwordConfirm
    ) {
      $this->session->set_flashdata('err', 'Gagal Registrasi');
      return redirect(base_url('backoffice/user/admin_add'));
    }

    if($check > 0) {
      $this->session->set_flashdata('err', 'Email sudah terdaftar.');
      return redirect(base_url('backoffice/user/admin_add'));
    }

    $add = $this->User_model->add_user($params);

    $this->session->set_flashdata('success', 'Berhasil Registrasi');

    return redirect(base_url('backoffice/user/admin_add'));
  }

  public function leader()
	{
    $this->data['page_title'] = 'Owner';
    $this->data['page'] = 'backoffice/user/leader';

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Owner',
        'link' => ''
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  } 

  public function leader_add()
	{
    $this->data['page_title'] = 'Tambah Leader';
    $this->data['page'] = 'backoffice/user/leader_add';

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Tambah Leader',
        'link' => ''
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function leader_add_post()
  {
    $passwordConfirm = htmlspecialchars($this->input->get('password_confirm', TRUE));
    $password = htmlspecialchars($this->input->get('password', TRUE));

    $params = [
      'first_name' => $this->input->post('first_name', TRUE),
      'last_name' => $this->input->post('last_name', TRUE),
      'email' => $this->input->post('email', TRUE),
      'password' => password_hash($this->input->post('password', TRUE), PASSWORD_BCRYPT),
      'referral' => $this->User_model->generate_referral(),
      'role' => 'owner'
    ];

    $check = $this->User_model->checkUser($params['email']);

    if(
      $params['first_name'] == '' ||
      $params['last_name'] == '' || 
      $params['email'] == '' ||
      $params['password'] == '' ||
      $password != $passwordConfirm
    ) {
      $this->session->set_flashdata('err', 'Gagal Registrasi');
      return redirect(base_url('backoffice/user/leader_add'));
    }

    if($check > 0) {
      $this->session->set_flashdata('err', 'Email sudah terdaftar.');
      return redirect(base_url('backoffice/user/leader_add'));
    }

    $add = $this->User_model->add_user($params);

    $this->session->set_flashdata('success', 'Berhasil Registrasi');

    return redirect(base_url('backoffice/user/leader_add'));
  }

  public function members()
	{
    $this->data['page_title'] = 'Member';
    $this->data['page'] = 'backoffice/user/member';

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Admin',
        'link' => ''
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function affiliators()
	{
    $this->data['page_title'] = 'Affiliator';
    $this->data['page'] = 'backoffice/user/affiliator';

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Admin',
        'link' => ''
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function affiliate_signup()
	{
    $this->data['page_title'] = 'Pendaftar Affiliasi';
    $this->data['page'] = 'backoffice/user/affiliator_signup';

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Admin',
        'link' => ''
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }
}
