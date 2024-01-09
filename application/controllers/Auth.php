<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Frontend_Controller.php';

class Auth extends Frontend_Controller {
  public function __construct()
  {
    parent::__construct();
		$this->load->model('User_model');
		$this->load->library('form_validation');
  }


  public function login()
  {
    if($this->data['is_login']) {
      return redirect(base_url());
    }
    $this->data['page'] = 'frontend/auth/v_login';
    $this->load->view('frontend/index', $this->data);
  }

  public function register()
  {
    if($this->data['is_login']) {
      return redirect(base_url());
    }
    $this->data['page'] = 'frontend/auth/v_register';
		$this->load->view('frontend/index', $this->data);
  }

  public function lupapassword()
  {
    if($this->data['is_login']) {
      return redirect(base_url());
    }
    $this->data['page'] = 'frontend/auth/v_lupapassword';
		$this->load->view('frontend/index', $this->data);

  } 
  public function logout()
  {
    $this->session->unset_userdata('user');
    $this->session->sess_destroy();
    return redirect(base_url());
  }

	public function doLogin()
	{
    validate_self_request();
    $email = htmlspecialchars($this->input->post('email', TRUE));
    $password = htmlspecialchars($this->input->post('password', TRUE));
    $redirect = htmlspecialchars($this->input->get('redirect', TRUE));
    $check = $this->User_model->checkAuth($email, $password);

    if(!$check) {
      $this->session->set_flashdata('err', 'Gagal Login, Coba lagi.');
      return redirect(base_url('auth/login?redirect=' . $redirect));
    }

    $token = $this->User_model->createToken($check);

    if(!$check || !$token) {
      $this->session->set_flashdata('err', 'Gagal Login, Coba lagi.');
      return redirect(base_url('auth/login?redirect=' . $redirect));
    }

		return redirect($redirect);
  }

  public function dolupapassword()
	{
    validate_self_request();
    $email = htmlspecialchars($this->input->post('email', TRUE));
    $redirect = htmlspecialchars($this->input->get('redirect', TRUE));

		$check = $this->db->query("select * from users where email = '".$email."'")->row_array();
		if (count($check) > 0) {
				$token = $this->_token();
				$user_token = [
						'email' => $email,
						'token' => $token,
						'date_created' => time()
				];
				$insert = $this->User_model->insert($user_token,'msusertoken');
				$ngimail = $this->_send_email($token, 'forgot');
				$this->session->set_flashdata('category_success', '<div class="alert alert-success" role="alert">
		Periksa email untuk reset password!</div>');
				redirect($redirect);
		} else {
				$this->session->set_flashdata('category_error', '<div class="alert alert-danger" role="alert">
		Email belum terdaftar!</div>');
				redirect(base_url('auth/lupapassword?redirect=' . $redirect));
		}

    // if(!$check) {
    //   $this->session->set_flashdata('err', 'Email Tidak Terdaftar.');
    //   return redirect(base_url('auth/lupapassword?redirect=' . $redirect));
    // }

		return redirect($redirect);
	}
	
	private function _send_email($token, $type)
	{
		require 'assets/PHPMailer/PHPMailerAutoload.php';


		$mail = new PHPMailer;

		// Konfigurasi SMTP
		$mail->isSMTP();
    $mail->Host = HOST_EMAIL;
		$mail->SMTPAuth = true;
		$mail->Username = EMAIL_BANTUAN;
		$mail->Password = PASSWORD_BANTUAN;
		$mail->SMTPSecure = 'tls';
		$mail->Port = EMAIL_PORT;
		$mail->setFrom(EMAIL_BANTUAN);
		// Menambahkan penerima
		$mail->addAddress($this->input->post('email'));
		if ($type == 'forgot') {
			// Subjek email
			$mail->Subject = 'Aneka Baru  - Reset Password';
			// Mengatur format email ke HTML
			$mail->isHTML(true);
			// Konten/isi email
			$mailContent = 'Klik untuk reset password akun anda  <a href="'.base_url().'auth/resetpassword?email='.$this->input->post('email').'&token='.urlencode($token).'">Reset Password</a>';
			$mail->Body = $mailContent;
		}

		// Kirim email
		if (!$mail->send()) {
			$pes = 'Pesan tidak dapat dikirim.';
			$mai = 'Mailer Error: ' . $mail->ErrorInfo;
		} else {
			$pes = 'Pesan telah terkirim';
		}
	}

	private function _token($length = 12)
    {
        $str = "";
        $characters = array_merge(range('A', 'Z'), range('a', 'z'), range('0', '9'));
        $max = count($characters) - 1;
        for ($i = 0; $i < $length; $i++) {
            $rand = mt_rand(0, $max);
            $str  .= $characters[$rand];
        }
        return $str;
    }

	public function resetpassword()
    {
        $email = $this->input->get('email');
        $token = $this->input->get('token');
        $user = $this->db->query("select * from users where email ='".$email."'")->row_array();
        if (count($user)>0)  {
            $token = ['token' => $token];
            $user_token = $this->db->query("select token from msusertoken where email ='".$email."'")->result_array();
            if ($user_token[0]) {
                $this->session->set_userdata('reset_email', $email);
                $this->changePassword();
            } else {
                $this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">
            Reset password gagal,token salah</div>');
                redirect('auth');
            }
        } else {
            $this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">
            Reset password gagal,Email salah</div>');
            redirect('auth');
        }
		}
		
		public function changepassword()
    {
        $this->form_validation->set_rules('password1', 'Password', 'required|trim|min_length[8]|matches[password2]');
        $this->form_validation->set_rules('password2', 'Password Ulang', 'required|trim|min_length[8]|matches[password1]');

        if ($this->form_validation->run() == false) {
						$this->data['page'] = 'frontend/auth/v_resetpassword';
						$this->load->view('frontend/index', $this->data);
        } else {
						$password = password_hash($this->input->post('password1', TRUE), PASSWORD_BCRYPT);
						
            $email = $this->session->userdata('reset_email');
            $this->db->set('password', $password);
            $this->db->set('updated_at', date('Y-m-d'));
            $this->db->where('email', $email);
            $this->db->update('users');
            $this->db->query("delete from msusertoken where email = '".$email."'");
            $this->session->unset_userdata('reset_email');
            $this->session->set_flashdata('message', '<div class="alert alert-success" role="alert">
            Password telah diubah,silahkan Login</div>');
            redirect(base_url());
        }
    }

  public function doRegister()
  {
    validate_self_request();
    $passwordConfirm = htmlspecialchars($this->input->get('password_confirm', TRUE));
    $password = htmlspecialchars($this->input->get('password', TRUE));
    $redirect = htmlspecialchars($this->input->get('redirect', TRUE));

    $params = [
      'first_name' => $this->input->post('first_name', TRUE),
      'last_name' => $this->input->post('last_name', TRUE),
      'email' => $this->input->post('email', TRUE),
      'phone' => $this->input->post('phone', TRUE),
      'password' => password_hash($this->input->post('password', TRUE), PASSWORD_BCRYPT),
      'referral' => $this->User_model->generate_referral(),
      'role' => $this->input->post('registrasi', TRUE) ?? 'member',
      'created_at' => date('Y-m-d H:i:s'),
      'updated_at' => date('Y-m-d H:i:s'),
    ];

    if($params['role'] == 'admin') {
      $params['role'] = 'member';
    }
    
    if($params['role'] == 'affiliate') {
	    if($leaderId = get_cookie('aff_data')) {
		    $checkLeader = $this->User_model->get_user($leaderId);
		    
		    if($checkLeader['role'] != 'leader') {
			    $this->session->set_flashdata('err', 'Untuk daftar sebagai Affiliator, harap melalui Refferral Leader');
			    return redirect(base_url('auth/register?redirect=' . $redirect));
		    }
		
		    $params['leader_id'] = $leaderId;
	    } else {
		    $this->session->set_flashdata('err', 'Untuk daftar sebagai Affiliator, harap melalui Refferral Leader');
		    return redirect(base_url('auth/register?redirect=' . $redirect));
	    }
    }
    
    if($affiliatorId = get_cookie('aff_data')) {
	    if($params['role'] == 'member') {
	        $checkAffiliator = $this->User_model->get_user($affiliatorId);
	    
    	    if($checkAffiliator['role'] != 'affiliate') {
    		    $this->session->set_flashdata('err', 'Referral ini hanya bisa daftar sebagai Affiliator. Jika ingin daftar sebagai Member silahkan pakai Referral Affiliator.');
    		    return redirect(base_url('auth/register?redirect=' . $redirect));
    	    }
    	
    	    $params['affiliator_id'] = $affiliatorId ?? 0;
	    }
    }
    
    // if($params['role'] != 'member' || $params['role'] != 'affiliate') {
    //   $this->session->set_flashdata('err', 'Gagal Registrasi');
    //   return redirect(base_url('auth/register?redirect=' . $redirect));
    // }

    $check = $this->User_model->checkUser($params['email']);

    if(
      $params['first_name'] == '' ||
      $params['last_name'] == '' || 
      $params['email'] == '' ||
      $params['password'] == '' ||
      $password != $passwordConfirm
    ) {
      $this->session->set_flashdata('err', 'Gagal Registrasi');
      return redirect(base_url('auth/register?redirect=' . $redirect));
    }

    if($check > 0) {
      $this->session->set_flashdata('err', 'Email sudah terdaftar.');
      return redirect(base_url('auth/register?redirect=' . $redirect));
    }

    $add = $this->User_model->add_user($params);

    $this->session->set_flashdata('success', 'Berhasil Registrasi');

    return redirect(base_url('auth/login?redirect=' . $redirect));
  }

  public function doRegisterAffiliator()
  {
    validate_self_request();
    $passwordConfirm = htmlspecialchars($this->input->get('password_confirm', TRUE));
    $password = htmlspecialchars($this->input->get('password', TRUE));
    $redirect = htmlspecialchars($this->input->get('redirect', TRUE));

    $params = [
      'leader_id' => $this->data['user']->id,
      'first_name' => $this->input->post('first_name', TRUE),
      'last_name' => $this->input->post('last_name', TRUE),
      'email' => $this->input->post('email', TRUE),
      'phone' => $this->input->post('phone', TRUE),
      'password' => password_hash($this->input->post('password', TRUE), PASSWORD_BCRYPT),
      'referral' => $this->User_model->generate_referral(),
      'role' => 'affiliate',
      'created_at' => date('Y-m-d H:i:s'),
      'updated_at' => date('Y-m-d H:i:s'),
    ];

    // if($params['role'] != 'member' || $params['role'] != 'affiliate') {
    //   $this->session->set_flashdata('err', 'Gagal Registrasi');
    //   return redirect(base_url('auth/register?redirect=' . $redirect));
    // }

    $check = $this->User_model->checkUser($params['email']);

    if(
      $params['first_name'] == '' ||
      $params['last_name'] == '' || 
      $params['email'] == '' ||
      $params['password'] == '' ||
      $password != $passwordConfirm
    ) {
      $this->session->set_flashdata('err', 'Gagal Registrasi');
      return redirect(base_url('member/my_affiliators?redirect=' . $redirect));
    }

    if($check > 0) {
      $this->session->set_flashdata('err', 'Email sudah terdaftar.');
      return redirect(base_url('member/my_affiliators?redirect=' . $redirect));
    }

    $add = $this->User_model->add_user($params);

    $this->session->set_flashdata('success', 'Berhasil Registrasi');

    return redirect(base_url('member/my_affiliators?redirect=' . $redirect));
  }

}
