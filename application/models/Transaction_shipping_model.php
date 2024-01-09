<?php

class Transaction_shipping_model extends CI_Model
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
        return $this->db->get_where('transaction_shippings',array('id'=>$id))->row_array();
    }

    function findByTransaction($id)
    {
        return $this->db->get_where('transaction_shippings',array('transaction_id'=>$id))->row();
    }
        
    /*
     * Get all transaction_shippings
     */
    function get_all_transaction_shippings()
    {
        $this->db->order_by('id', 'desc');
        return $this->db->get('transaction_shippings')->result_array();
    }
        
    /*
     * function to add new transaction
     */
    function add_transaction($params)
    {
        $this->db->insert('transaction_shippings',$params);
        return $this->db->insert_id();
    }

    function add_batch($params)
    {
      $insert = $this->db->insert_batch('transaction_shippings',$params);

      if(!$insert) return false;

      return true;
    }
    
    /*
     * function to update transaction
     */
    function update_transaction($id,$params)
    {
        $this->db->where('id',$id);
        return $this->db->update('transaction_shippings',$params);
    }

    function updateByTransaction($id,$params)
    {
        $this->db->where('transaction_id',$id);
        return $this->db->update('transaction_shippings',$params);
    }
    
    /*
     * function to delete transaction
     */
    function delete_transaction($id)
    {
        return $this->db->delete('transaction_shippings',array('id'=>$id));
    }
}
