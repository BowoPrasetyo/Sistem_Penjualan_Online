<?php

 
class Widthdraw_affiliate_model extends CI_Model
{
    function __construct()
    {
        parent::__construct();
    }
    
    /*
     * Get withdraw_affiliates by id
     */
    function get_withdraw_affiliate($id)
    {
        return $this->db->get_where('withdraw_affiliates',array('id'=>$id))->row_array();
    }

    function get_latest_withdraw($user)
    {
        return $this->db->order_by('id', 'DESC')->get_where('withdraw_affiliates',array('user_id'=>$user))->row_array();
    }

    function detail_with_user($id)
    {
        return $this->db
            ->select('
                withdraw_affiliates.id,
                withdraw_affiliates.user_id,
                users.first_name as user_first_name,
                users.last_name as user_last_name,
                users.account_name,
                users.bank_name,
                users.account_number,
                withdraw_affiliates.bank_id,
                withdraw_affiliates.amount,
                withdraw_affiliates.status,
                withdraw_affiliates.created_at,
                withdraw_affiliates.updated_at,
            ')
            ->join('users', 'withdraw_affiliates.user_id=users.id')
            ->get_where('withdraw_affiliates',array('withdraw_affiliates.id'=>$id))->row_array();
    }
        
    /*
     * Get all withdraw_affiliatess
     */
    function get_all_withdraw_affiliatess()
    {
        $this->db->order_by('id', 'desc');
        return $this->db->get('withdraw_affiliates')->result_array();
    }
        
    /*
     * function to add new withdraw_affiliates
     */
    function add_withdraw_affiliate($params)
    {
        $this->db->insert('withdraw_affiliates',$params);
        return $this->db->insert_id();
    }
    
    /*
     * function to update withdraw_affiliates
     */
    function update_withdraw_affiliate($id,$params)
    {
        $this->db->where('id',$id);
        return $this->db->update('withdraw_affiliates',$params);
    }
    
    /*
     * function to delete withdraw_affiliates
     */
    function delete_withdraw_affiliate($id)
    {
        return $this->db->delete('withdraw_affiliates',array('id'=>$id));
    }

    function datatable($user = null) {
        $this->datatables->select('
            withdraw_affiliates.id,
            withdraw_affiliates.user_id,
            users.first_name as user_first_name,
            users.last_name as user_last_name,
            users.account_name,
            users.bank_name,
            users.account_number,
            withdraw_affiliates.bank_id,
            withdraw_affiliates.amount,
            withdraw_affiliates.status,
            withdraw_affiliates.created_at,
            withdraw_affiliates.updated_at,
        '
        );

        
        $this->datatables->from('withdraw_affiliates');
        if($user != null) {
            $this->datatables->where('withdraw_affiliates.user_id', $user);
        }

        $status = $this->input->post('columns')[3]['search']['value'] ?? null;

        if($status != null && $status != 'all') {
            $this->datatables->where('withdraw_affiliates.item_status', $status);
        }

        $parameterData = $this->input->get('data');
        if($parameterData == 'today') {
            $start = date('Y-m-d') . ' 00:00';
            $end = date('Y-m-d') . ' 23:59';
            $this->datatables->where('withdraw_affiliates.created_at >= ', date('Y-m-d H:i:s', strtotime($start)));
            $this->datatables->where('withdraw_affiliates.created_at <= ', date('Y-m-d H:i:s', strtotime($end)));
        }

        if($parameterStatus = $this->input->get('status')) {
            $this->datatables->where('withdraw_affiliates.item_status', $parameterStatus);
        }

        $this->datatables->join('users', 'withdraw_affiliates.user_id=users.id');
        //add this line for join
        $this->datatables->add_column('action', "<a href='".base_url()."backoffice/withdraw/detail/$1' class='btn btn-sm btn-info btn-info-gradient'><i class='fas fa-eye'></i> Detail</a>", 'id');
        return $this->datatables->generate();
    }
}
