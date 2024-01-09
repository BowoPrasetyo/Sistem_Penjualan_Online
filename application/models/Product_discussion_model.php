<?php
 
class Product_discussion_model extends CI_Model
{
    function __construct()
    {
        parent::__construct();
    }
    
    /*
     * Get product_discussion by id
     */
    function get_product_discussion($id)
    {
        return $this->db->get_where('product_discussions',array('id'=>$id))->row_array();
    }
        
    /*
     * Get all product_discussions
     */
    function get_all_product_discussions($where = null)
    {
        $this->db->order_by('id', 'desc');

        if($where != null) {
            $this->db->where($where);
        }

        $this->db->limit(10);

        return $this->db->get('product_discussions')->result_array();
    }
        
    /*
     * function to add new product_discussion
     */
    function add_product_discussion($params)
    {
        $this->db->insert('product_discussions',$params);
        return $this->db->insert_id();
    }
    
    /*
     * function to update product_discussion
     */
    function update_product_discussion($id,$params)
    {
        $this->db->where('id',$id);
        return $this->db->update('product_discussions',$params);
    }
    
    /*
     * function to delete product_discussion
     */
    function delete_product_discussion($id)
    {
        return $this->db->delete('product_discussions',array('id'=>$id));
    }
}
