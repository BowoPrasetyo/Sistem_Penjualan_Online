<?php
 
class User_model extends CI_Model
{
    function __construct()
    {
        parent::__construct();
    }
    
    /*
     * Get user by id
     */
    function get_user($id)
    {
        return $this->db->get_where('users',array('id'=>$id))->row_array();
    }
        
    function findByReferral($referral)
    {
        return $this->db->get_where('users',array('referral'=>$referral))->row_array();
    }
    /*
     * Get all users
     */
    function get_all_users()
    {
        $this->db->order_by('id', 'desc');
        return $this->db->get('users')->result_array();
    }
        
    /*
     * function to add new user
     */
    function add_user($params)
    {
        $this->db->insert('users',$params);
        return $this->db->insert_id();
    }

    public function generate_referral(){
		do{
		$length = 5;
		$randomletter = substr(str_shuffle("abcdefghijklmnopqrstuvwxyz1234567890"), 0, $length);
		$referral='mgt'.$randomletter.mt_rand(10,100);
		$a = $this->db->get_where('users',array('referral'=>$referral))->num_rows();
		}while($a > 0);
		
		return $referral    ;		
	}
    
    /*
     * function to update user
     */
    function update_user($id,$params)
    {
        $this->db->where('id',$id);
        return $this->db->update('users',$params);
    }
    
    /*
     * function to delete user
     */
    function delete_user($id)
    {
        return $this->db->delete('users',array('id'=>$id));
    }
    function checkUser($email)
    {
        return $this->db->get_where('users',array('email'=>$email))->num_rows();
    }

    public function checkAuth($email = '', $password = '')
    {
        $check = $this->db
        ->where('email', $email)
        ->where_in('role', [
            'member',
            'affiliate',
            'developer',
            'provider',
			'leader',
			'owner',
            'mediator',
            'cs'
        ])
        ->get('users');
        
        if($check->num_rows() > 0) {
        $data = $check->row();

        if(password_verify($password, $data->password)) {
            $this->setLogin($data);
            return $data;
         }
        } 

        return false;
    }

	public function insert($data, $table)
    {
        $result = $this->db->insert($table, $data);
        return $result;
	}
	
    public function checkAuthAdmin($email = '', $password = '')
    {
        $check = $this->db
        ->where('email', $email)
        ->get('users');
        
        if($check->num_rows() > 0) {
        $data = $check->row();

        if(password_verify($password, $data->password)) {
            $this->setLoginAdmin($data);
            return $data;
         }
        } 

        return false;
    }

    public function setLogin($data)
    {
        $data = array(
            'user'  => $data,
            'logged_in' => TRUE
        );
        
        if(!$this->session->set_userdata($data)) {
            return false;
        }

        return true;
    }

    public function setLoginAdmin($data)
    {
        $data = array(
			'admin'  => $data,
			'role' => $data->role,
			'logged_in' => TRUE,
        );
        if(!$this->session->set_userdata($data)) {
            return false;
        }

        return true;
    }

    public function createToken($user = null) {

        $data['token_expired'] = time() * 60 * 10;
        $data['token'] = password_hash($data['token_expired'], PASSWORD_BCRYPT);

        $update = $this->db
        ->where('id', $user->id)
        ->where('email', $user->email)
        ->set('token_expired', $data['token_expired'])
        ->set('token', $data['token'])
        ->update('users');

        if(!$update) return false;

        return $data['token'];
    }

    public function checkToken($token = '')
    {
        $check = $this->db
        ->where('token', $token)
        ->get('users');

        if($check->num_rows() <= 0) return false;

        $afterCheck = $check->row();

        if($afterCheck->token_expired < time()) return false;

        return $afterCheck;
    }

    public function pagination($limit = 10, $start = 0, $path = '')
    {
        $offset =  $start == 0 ? 0 : ($start + $limit) - 1;
        $query = $this->db
        ->limit($limit, $offset);

        if ($sort = $this->input->get('sort')) {
        list($sortCol, $sortDir) = explode('|', $sort);
            $query->order_by($sortCol, $sortDir);
        } else {
            $query->order_by('x1.created_at', 'DESC');
        }
        
        if ($q = $this->input->get('q')) {
            $query->like('x1.name', $q);
        }

    
        $data = $query->get('users x1')
        ->result();

        $total = $this->countTotal();

        $currentPage = (int) $start + 1;
        $totalPage = ceil($total / $limit);
        $nextPage = ($currentPage + 1) > $totalPage ? null : "{$path}?page=" . ($currentPage + 1);

        return [
            'success' => true,
            'message' => 'Success Get users',
            'current_page' => $currentPage,
            'data' => $data,
            'first_page_url' => "{$path}?page=1",
            'from' => $total - $currentPage,
            'last_page' => $totalPage,
            'last_page_url' => "{$path}?page=$totalPage",
            'next_page_url' => $nextPage,
            'path' => $path,
            'per_page' => $limit,
            'prev_page_url' => "{$path}?page=" . ($currentPage - 1),
            'to' => $total - $currentPage,
            'total' => $total
        ];
    }

    public function countTotal($status = null)
    {
        $query =  $this->db;

        return $query->get('users')->num_rows();
    }

    public function count_member($role)
    {
        $query =  $this->db->where('role', $role ?? 'member');

        return $query->get('users')->num_rows();
    }

    function affiliates($user = null) {
        $this->datatables->select('
            users.id,
            users.first_name,
            users.last_name,
            users.email,
        '
        );
        
        $this->datatables->from('users');

        $this->datatables->where('users.role', 'affiliate');

        //add this line for join
        $this->datatables->add_column('action', "<a href='".base_url()."member/transaction_detail/$1' class='btn btn-sm btn-info btn-info-gradient'><i class='fas fa-eye'></i> Detail</a>", 'order_id');
        return $this->datatables->generate();
    }

    function affiliators($leader = null) {
        $this->datatables->select('
            users.id,
            users.first_name,
            users.last_name,
            users.email,
            users.phone,
            users.created_at
        '
        );
        
        $this->datatables->from('users');

        $this->datatables->where('users.leader_id', $leader);

        //add this line for join
        $this->datatables->add_column('action', "<a href='".base_url()."member/transaction_detail/$1' class='btn btn-sm btn-info btn-info-gradient'><i class='fas fa-eye'></i> Detail</a>", 'order_id');
        return $this->datatables->generate();
    }

    function members($user = null) {
        $this->datatables->select('
            users.id,
            users.first_name,
            users.last_name,
            users.email,
        '
        );
        
        $this->datatables->from('users');

        $this->datatables->where('users.role', 'member');

        //add this line for join
        $this->datatables->add_column('action', "<a href='".base_url()."member/transaction_detail/$1' class='btn btn-sm btn-info btn-info-gradient'><i class='fas fa-eye'></i> Detail</a>", 'order_id');
        return $this->datatables->generate();
    }

    function leaders($user = null) {
        $this->datatables->select('
            users.id,
            users.first_name,
            users.last_name,
            users.email,
        '
        );
        
        $this->datatables->from('users');

        $this->datatables->where('users.role', 'owner');

        //add this line for join
        $this->datatables->add_column('action', "<a href='".base_url()."member/transaction_detail/$1' class='btn btn-sm btn-info btn-info-gradient'><i class='fas fa-eye'></i> Detail</a>", 'order_id');
        return $this->datatables->generate();
    }

    function admins($user = null) {
        $this->datatables->select('
            users.id,
            users.first_name,
            users.last_name,
            users.email,
        '
        );
        
        $this->datatables->from('users');

        $this->datatables->where('users.role', 'admin');

        //add this line for join
        $this->datatables->add_column('action', "<a href='".base_url()."member/transaction_detail/$1' class='btn btn-sm btn-info btn-info-gradient'><i class='fas fa-eye'></i> Detail</a>", 'order_id');
        return $this->datatables->generate();
    }

    public function paginationMember($limit = 10, $start = 0, $path = '')
    {
        $offset =  $start == 0 ? 0 : ($start + $limit) - 1;
        $query = $this->db
        ->where('role', 'member')
        ->limit($limit, $offset);

        if ($sort = $this->input->get('sort')) {
        list($sortCol, $sortDir) = explode('|', $sort);
            $query->order_by($sortCol, $sortDir);
        } else {
            $query->order_by('x1.created_at', 'DESC');
        }
        
        if ($q = $this->input->get('q')) {
            $query->like('x1.name', $q);
        }

    
        $data = $query->get('users x1')
        ->result();

        $total = $this->countTotalMember();

        $currentPage = (int) $start + 1;
        $totalPage = ceil($total / $limit);
        $nextPage = ($currentPage + 1) > $totalPage ? null : "{$path}?page=" . ($currentPage + 1);

        return [
        'success' => true,
        'message' => 'Success Get users',
        'current_page' => $currentPage,
        'data' => $data,
        'first_page_url' => "{$path}?page=1",
        'from' => $total - $currentPage,
        'last_page' => $totalPage,
        'last_page_url' => "{$path}?page=$totalPage",
        'next_page_url' => $nextPage,
        'path' => $path,
        'per_page' => $limit,
        'prev_page_url' => "{$path}?page=" . ($currentPage - 1),
        'to' => $total - $currentPage,
        'total' => $total
        ];
    }

    public function countTotalMember($status = null)
    {
        $query =  $this->db;

        return $query->where('role', 'member')->get('users')->num_rows();
    }
}
