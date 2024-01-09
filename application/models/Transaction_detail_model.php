<?php

class Transaction_detail_model extends CI_Model
{
    function __construct()
    {
        parent::__construct();
    }
    
    /*
     * Get transaction by id
     */
    function get_transaction_detail($id)
    {
        return $this->db->get_where('transaction_details',array('id'=>$id))->row_array();
    }

    function findByTransaction($id)
    {
        return $this->db
            ->select('
              x1.product,
              x1.id as detail_id,
              x1.quantity,
              x1.price,
              x1.delivery_status,
              x1.total_commision_maintenance,
              x1.total_commision_affiliator,
              x1.total_commision_provider,
              x1.total_commision_mediator,
              x1.total_commision_leader,
              x1.total_commision_cs,
            ')
            // ->join('products x2', 'x1.product_id=x2.id')
            ->get_where('transaction_details x1',array('x1.transaction_id'=>$id))->result();
    }
        
    /*
     * Get all transaction_details
     */
    function get_all_transaction_details()
    {
        $this->db->order_by('id', 'desc');
        return $this->db->get('transaction_details')->result_array();
    }
        
    /*
     * function to add new transaction
     */
    function add_transaction_detail($params)
    {
        $this->db->insert('transaction_details',$params);
        return $this->db->insert_id();
    }

    function add_batch($params)
    {
      $insert = $this->db->insert_batch('transaction_details',$params);

      if(!$insert) return false;

      return true;
    }

    public function commision()
    {
        $this->db->select('x1.*, sum(x1.quantity) as total_sales');
        $this->db->join('transactions x2', 'x1.transaction_id=x2.id');
        $this->db->where_in('x2.item_status', ['pending', 'complete', 'send']);
        $this->db->group_by('x1.product_id');
        return $this->db->get('transaction_details x1')->result();
    }
    
    /*
     * function to update transaction
     */
    function update_transaction($id,$params)
    {
        $this->db->where('id',$id);
        return $this->db->update('transaction_details',$params);
    }

    function updateByTransaction($id,$params)
    {
        $this->db->where('transaction_id',$id);
        return $this->db->update('transaction_details',$params);
    }
    
    /*
     * function to delete transaction
     */
    function delete_transaction($id)
    {
        return $this->db->delete('transaction_details',array('id'=>$id));
    }
}
