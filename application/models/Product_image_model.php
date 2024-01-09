<?php

 
class Product_image_model extends CI_Model
{
    function __construct()
    {
        parent::__construct();
    }
    
    /*
     * Get product_image by id
     */
    function get_product_image($id)
    {
        return $this->db->get_where('product_images',array('id'=>$id))->row_array();
    }

    function find_by_product($ref)
    {
        return $this->db->order_by('is_thumbnail', 'DESC')->get_where('product_images',array('product_ref'=>$ref))->result();
    }
        
    /*
     * Get all product_images
     */
    function get_all_product_images()
    {
        $this->db->order_by('id', 'desc');
        return $this->db->get('product_images')->result_array();
    }
        
    /*
     * function to add new product_image
     */
    function add_product_image($params)
    {
        $this->db->insert('product_images',$params);
        return $this->db->insert_id();
    }
    
    /*
     * function to update product_image
     */
    function update_product_image($id,$params)
    {
        $this->db->where('id',$id);
        return $this->db->update('product_images',$params);
    }
    
    /*
     * function to delete product_image
     */
    function delete_product_image($id)
    {
        return $this->db->delete('product_images',array('id'=>$id));
    }
}
