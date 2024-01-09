<?php

class Transaction_model extends CI_Model
{
    function __construct()
    {
        parent::__construct();
    }
    
    /*
     * Get transaction by id
     */
    function get_transaction($id)
    {
        return $this->db->get_where('transactions',array('id'=>$id))->row_array();
    }

    function get_transaction_commision($id)
    {
        return $this->db->get_where('transactions',array('id'=>$id, 'is_share_commision' => 0))->row_array();
    }

    function findByOrderIdUser($order_id = 0, $user = 0)
    {
        return $this->db->get_where('transactions',array('order_id'=>$order_id, 'user_id' => $user))->row_array();
    }

    function findByTransactionUser($id, $user = 0)
    {
        return $this->db->get_where('transactions',array('id'=>$id, 'user_id' => $user))->row_array();
    }

    function findByOrderId($id)
    {
        return $this->db->get_where('transactions',array('order_id'=>$id))->row();
    }

    function findByUserId($id)
    {
        return $this->db->get_where('transactions',array('user_id'=>$id))->result();
    }
    
    function get_total_valid_order()
    {
        return $this->db
            ->select('SUM(transaction_details.quantity) as total')
            ->join('transactions', 'transaction_details.transaction_id=transactions.id')
            ->where_in('transactions.item_status', ['complete'])
            ->get('transaction_details')->row()->total;
    }
    
    function total_valid_transaction()
    {
        return $this->db
            ->join('transactions', 'transaction_details.transaction_id=transactions.id')
            ->where_in('transactions.item_status', ['complete'])
            ->get('transaction_details')->num_rows();
    }
    
    function pesanan_diproses()
    {
        return $this->db
            ->join('transactions', 'transaction_details.transaction_id=transactions.id')
            ->where_in('transactions.item_status', ['process'])
            ->get('transaction_details')->num_rows();
    }
    
    function pesanan_dikirim()
    {
        return $this->db
            ->join('transactions', 'transaction_details.transaction_id=transactions.id')
            ->where_in('transactions.item_status', ['send'])
            ->get('transaction_details')->num_rows();
    }
        
    /*
     * Get all transactions
     */
    function get_all_transactions()
    {
        $this->db->order_by('id', 'desc');
        return $this->db->get('transactions')->result_array();
    }
        
    /*
     * function to add new transaction
     */
    function add_transaction($params)
    {
        $this->db->insert('transactions',$params);
        return $this->db->insert_id();
    }
    
    /*
     * function to update transaction
     */
    function update_transaction($id,$params)
    {
        $this->db->where('id',$id);
        return $this->db->update('transactions',$params);
    }

    function update_receipt($id,$receipt)
    {
        $this->db->where('id',$id);
        $this->db->set('no_receipt', $receipt);
        return $this->db->update('transactions');
    }
    
    /*
     * function to delete transaction
     */
    function delete_transaction($id)
    {
        return $this->db->delete('transactions',array('id'=>$id));
    }

    public function pagination($limit = 10, $start = 0, $path = '')
    {
        $offset =  $start == 0 ? 0 : ($start + $limit) - 1;
        $query = $this->db
        ->select('x1.*, x2.first_name as user_first_name, x2.last_name as user_last_name')
        ->join('users x2', 'x1.user_id=x2.id', 'LEFT_JOIN')
        ->limit($limit, $offset);

        if ($sort = $this->input->get('sort')) {
        list($sortCol, $sortDir) = explode('|', $sort);
            $query->order_by($sortCol, $sortDir);
        } else {
            $query->order_by('x1.created_at', 'DESC');
        }
        
        if ($q = $this->input->get('q')) {
            $query->like('x1.order_id', $q);
        }

    
        $data = $query->get('transactions x1')
        ->result();

        $total = $this->countTotal();

        $currentPage = (int) $start + 1;
        $totalPage = ceil($total / $limit);
        $nextPage = ($currentPage + 1) > $totalPage ? null : "{$path}?page=" . ($currentPage + 1);

        return [
        'success' => true,
        'message' => 'Success Get transactions',
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

        return $query->get('transactions')->num_rows();
    }

    public function get_earning_today()
    {
        $start = date('Y-m-d') . ' 00:00';
        $end = date('Y-m-d') . ' 23:59';
        $data = $this->db
        ->select('sum(transactions.amount) as earning_today')
        ->where('transactions.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
        ->where('transactions.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
        ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
        ->get('transactions')->row();
        return $data ? $data->earning_today : 0;
    }

    public function generate_unique()
    {
        $start = date('Y-m-d') . ' 00:00';
        $end = date('Y-m-d') . ' 23:59';

        $last = $this->db
            ->order_by('id', 'DESC')
//            ->where('created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
//            ->where('created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
            ->get('transactions');

        if($last->num_rows() > 0) {
            return (int) $last->row()->unique + 1;
        }

        return 100;
    }

    public function get_order_today()
    {
        $start = date('Y-m-d') . ' 00:00';
        $end = date('Y-m-d') . ' 23:59';
        $data = $this->db
        ->where('transactions.created_at >= ', date('Y-m-d H:i:s', strtotime($start)))
        ->where('transactions.created_at <= ', date('Y-m-d H:i:s', strtotime($end)))
        ->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process'])
        ->get('transactions')->num_rows();
        return $data ? $data : 0;
    }


    function datatable($user = null) {
        $this->datatables->select('
            transactions.id,
            transactions.user_id,
            transactions.affiliate_id,
            transactions.order_id,
            transactions.amount,
            transactions.snap_token,
            transactions.fraud_status,
            transactions.item_status,
            transactions.expired_time,
            transactions.created_at,
            transactions.no_receipt,
            transactions.cash_on_delivery,
            transactions.cash_on_delivery_markup,
        '
        );

        
        $this->datatables->from('transactions');
        if($user != null) {
            $this->datatables->where('transactions.user_id', $user);
        }

        $status = $this->input->post('columns')[3]['search']['value'] ?? null;

        if($status != null && $status != 'all') {
            $this->datatables->where('transactions.item_status', $status);
        }

        $parameterData = $this->input->get('data');
        if($parameterData == 'today') {
            $start = date('Y-m-d') . ' 00:00';
            $end = date('Y-m-d') . ' 23:59';
            $this->datatables->where('transactions.created_at >= ', date('Y-m-d H:i:s', strtotime($start)));
            $this->datatables->where('transactions.created_at <= ', date('Y-m-d H:i:s', strtotime($end)));
        }

        if($parameterStatus = $this->input->get('status')) {
            $this->datatables->where('transactions.item_status', $parameterStatus);
        }
        //add this line for join
        $this->datatables->add_column('current_time', date("Ymdhis"), 'id');
        $this->datatables->add_column('action', "<a href='".base_url()."member/transaction_detail/$1' class='btn btn-sm btn-info btn-info-gradient'><i class='fas fa-eye'></i> Detail</a>", 'order_id');
        return $this->datatables->generate();
    }

    function commision($user = null) {
        $this->datatables->select('
            transactions.id,
            transactions.user_id,
            transactions.affiliate_id,
            transactions.order_id,
            transactions.amount,
            transactions.fraud_status,
            transactions.item_status,
            transactions.created_at,
            transactions.no_receipt,
            transactions.cash_on_delivery,
            transaction_details.total_commision_maintenance,
            transaction_details.total_commision_affiliator,
            transaction_details.total_commision_provider,
            transaction_details.total_commision_leader,
            transaction_details.total_commision_mediator,
            transaction_details.total_commision_cs,
            transactions.cash_on_delivery_markup,
        '
        );

        
        $this->datatables->from('transactions');
        if($user != null) {
            if($this->session->userdata('user')->role == 'affiliate') {
                $this->datatables->where('transactions.affiliate_id', $user);
            }
        }


        $startDate = $this->input->get('start');
        $endDate = $this->input->get('end');
        
        if($startDate && $endDate) {
            $start = date('Y-m-d', strtotime($startDate)) . ' 00:00';
            $end = date('Y-m-d', strtotime($endDate)) . ' 23:59';
            $this->datatables->where('transactions.created_at >= ', date('Y-m-d H:i:s', strtotime($start)));
            $this->datatables->where('transactions.created_at <= ', date('Y-m-d H:i:s', strtotime($end)));
        }

        // if($parameterStatus = $this->input->get('status')) {
        //     $this->datatables->where('transactions.item_status', $parameterStatus);
        // }

        $this->datatables->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process']);
        $this->datatables->join('transaction_details', 'transactions.id=transaction_details.transaction_id');
        //add this line for join
        $this->datatables->add_column('action', "<a href='".base_url()."member/transaction_detail/$1' class='btn btn-sm btn-info btn-info-gradient'><i class='fas fa-eye'></i> Detail</a>", 'order_id');
        return $this->datatables->generate();
    }

    function commision_backoffice($user = null) {
        $this->datatables->select('
            transactions.id,
            transactions.user_id,
            transactions.affiliate_id,
            transactions.order_id,
            transactions.amount,
            transactions.fraud_status,
            transactions.item_status,
            transactions.created_at,
            transactions.no_receipt,
            transactions.cash_on_delivery,
            transactions.cash_on_delivery_markup,
            transaction_details.total_commision_maintenance,
            transaction_details.total_commision_affiliator,
            transaction_details.total_commision_provider,
            transaction_details.total_commision_leader,
            transaction_details.total_commision_mediator,
            transaction_details.total_commision_cs,
            users.role as user_role
        '
        );

        
        $this->datatables->from('transactions');
        if($user != null) {
            $this->datatables->where('transactions.affiliate_id', $user);
        }


        $startDate = $this->input->get('start');
        $endDate = $this->input->get('end');
        
        if($startDate && $endDate) {
            $start = date('Y-m-d', strtotime($startDate)) . ' 00:00';
            $end = date('Y-m-d', strtotime($endDate)) . ' 23:59';
            $this->datatables->where('transactions.created_at >= ', date('Y-m-d H:i:s', strtotime($start)));
            $this->datatables->where('transactions.created_at <= ', date('Y-m-d H:i:s', strtotime($end)));
        }

        // if($parameterStatus = $this->input->get('status')) {
        //     $this->datatables->where('transactions.item_status', $parameterStatus);
        // }

        $this->datatables->where_in('transactions.item_status', ['pending', 'send', 'complete', 'process']);
        $this->datatables->join('transaction_details', 'transactions.id=transaction_details.transaction_id');
        $this->datatables->join('users', 'transactions.affiliate_id=users.id');
        //add this line for join
        $this->datatables->add_column('action', "<a target='_blank' href='".base_url()."backoffice/transaction/detail/$1' class='btn btn-sm btn-info btn-info-gradient'><i class='fas fa-eye'></i> Detail</a>", 'order_id');
        return $this->datatables->generate();
    }

    function datatable_backoffice($user = null) {
        $this->datatables->select('
            transactions.id,
            transactions.user_id,
            transactions.affiliate_id,
            transactions.order_id,
            transactions.amount,
            transactions.fraud_status,
            transactions.item_status,
            transactions.created_at,
            transactions.no_receipt,
            transactions.created_at,
            transactions.cash_on_delivery,
            transactions.cash_on_delivery_markup,
            users.email as user_email,
            users.first_name as user_first_name,
            users.last_name as user_last_name
        '
        );

        
        $this->datatables->from('transactions');
        if($user != null) {
            $this->datatables->where('transactions.user_id', $user);
        }

        $status = $this->input->post('columns')[3]['search']['value'] ?? null;

        if($status != null && $status != 'all') {
            $this->datatables->where('transactions.item_status', $status);
        }

        $startDate = $this->input->get('start');
        $endDate = $this->input->get('end');
        
        if($startDate && $endDate) {
            $start = date('Y-m-d', strtotime($startDate)) . ' 00:00';
            $end = date('Y-m-d', strtotime($endDate)) . ' 23:59';
            $this->datatables->where('transactions.created_at >= ', date('Y-m-d H:i:s', strtotime($start)));
            $this->datatables->where('transactions.created_at <= ', date('Y-m-d H:i:s', strtotime($end)));
        }

        $parameterData = $this->input->get('data');
        if($parameterData == 'today') {
            $start = date('Y-m-d') . ' 00:00';
            $end = date('Y-m-d') . ' 23:59';
            $this->datatables->where('transactions.created_at >= ', date('Y-m-d H:i:s', strtotime($start)));
            $this->datatables->where('transactions.created_at <= ', date('Y-m-d H:i:s', strtotime($end)));
        }

        if($parameterStatus = $this->input->get('status')) {
            $this->datatables->where('transactions.item_status', $parameterStatus);
        }

        $this->datatables->join('users', 'transactions.user_id=users.id');
        //add this line for join
        $this->datatables->add_column('action', "<a href='".base_url()."backoffice/transaction/detail/$1' class='btn btn-sm btn-info btn-info-gradient'><i class='fas fa-eye'></i> Detail</a>", 'order_id');
        return $this->datatables->generate();
    }

    public function paginationMember($limit = 10, $start = 0, $path = '', $user = 0)
    {
        $offset =  $start == 0 ? 0 : ($start + $limit) - 1;
        $query = $this->db
        ->select('x1.*, x2.first_name as user_first_name, x2.last_name as user_last_name')
        ->join('users x2', 'x1.user_id=x2.id', 'LEFT_JOIN')
        ->where('x1.user_id', $user)
        ->limit($limit, $offset);

        if ($sort = $this->input->get('sort')) {
        list($sortCol, $sortDir) = explode('|', $sort);
            $query->order_by($sortCol, $sortDir);
        } else {
            $query->order_by('x1.created_at', 'DESC');
        }
        
        if ($q = $this->input->get('q')) {
            $query->like('x1.order_id', $q);
        }

    
        $data = $query->get('transactions x1')
        ->result();

        $total = $this->countTotalMember();

        $currentPage = (int) $start + 1;
        $totalPage = ceil($total / $limit);
        $nextPage = ($currentPage + 1) > $totalPage ? null : "{$path}?page=" . ($currentPage + 1);

        return [
        'success' => true,
        'message' => 'Success Get transactions',
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

        return $query->get('transactions')->num_rows();
    }
}
