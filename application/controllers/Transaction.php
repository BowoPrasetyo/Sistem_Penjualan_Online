<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Frontend_Controller.php';

class Transaction extends Frontend_Controller{
    function __construct()
    {
        parent::__construct();
        $params = array(
            'server_key' => $this->data['setting_midtrans_mode'] == 'dev' ? $this->data['setting_midtrans_server_key_dev'] : $this->data['setting_midtrans_server_key'], 
            'production' => $this->data['setting_midtrans_mode'] == 'dev' ? false : true
        );
        $this->load->library('midtrans');
        $this->midtrans->config($params);
        $this->load->model('Transaction_model');
        $this->load->model('Product_model');
        $this->load->model('User_model');
        $this->load->model('Transaction_detail_model');
        $this->load->model('Transaction_shipping_model');
        $this->load->model('Commision_model');
        $this->load->model('Notification_model');
        $this->load->library('cart');
    } 

    public function member()
    {
        validate_self_request();
        header('Content-Type: application/json');
        echo $this->Transaction_model->datatable(
            $this->session->userdata('user')->id
        );
    }

    public function commision()
    {
        validate_self_request();
        header('Content-Type: application/json');
        echo $this->Transaction_model->commision($this->session->userdata('user')->id ?? null);
    }

    public function all()
    {
        $currentPage = $this->input->get('page') ?? 1;

        $page = $currentPage == 1 ? 0 : (int) $this->input->get('page') - 1;

        return toJson($this->Transaction_model->pagination(
            $this->input->get('per_page') ?? 10,
            $page,
            base_url('transaction/all')
        ));
    }

    public function members()
    {
        validate_self_request();
        $currentPage = $this->input->get('page') ?? 1;

        $page = $currentPage == 1 ? 0 : (int) $this->input->get('page') - 1;

        return toJson($this->Transaction_model->paginationMember(
            $this->input->get('per_page') ?? 10,
            $page,
            base_url('transaction/members'),
            $this->_authUser->id ?? 0
        ));
    }

    /*
     * Listing of transactions
     */
    function index()
    {
        validate_self_request();
        $data['transactions'] = $this->Transaction_model->get_all_transactions();
        
        return toJson([
            'success' => true,
            'data' => $data['transactions']
        ]);
    }

    function update_receipt($id)
    {
        validate_self_request();
        $receipt = inputPost('no_receipt');
        $this->Transaction_model->update_receipt($id, $receipt);

        return toJson([
            'success' => true,
            'data' => $receipt
        ]);
    }

    function detail($id)
    {
        validate_self_request();
        $data['transaction'] = $this->Transaction_model->get_transaction($id);
        $data['product'] = $this->Transaction_detail_model->findByTransaction($id);
        $data['shipping'] = $this->Transaction_shipping_model->findByTransaction($id);

        return toJson([
            'success' => true,
            'data' => $data
        ]);
    }

    function detail_member($id)
    {
        validate_self_request();
        $userId = $this->_authUser->id ?? 0;
        
        $data['transaction'] = $this->Transaction_model->findByTransactionUser($id, $userId);
        if($data['transaction'] != null) {
            $data['product'] = $this->Transaction_detail_model->findByTransaction($data['transaction']['id']);
            $data['shipping'] = $this->Transaction_shipping_model->findByTransaction($data['transaction']['id']);   
        } else {
            $data = [];
        }

        return toJson([
            'success' => true,
            'data' => $data,
        ]);
    }

    public function create_transaction()
    {
        try {
            if(isset($_POST) > 0) {
                validate_self_request();
                if(count($this->cart->contents()) <= 0) {
                    return toJson([
                        'success' => false,
                        'data' => null
                    ]);
                }

                $this->db->trans_start();

                $params = [
                    'recipient_name' => htmlspecialchars($this->input->post('recipient_name', TRUE)),
                    'recipient_address' => htmlspecialchars($this->input->post('recipient_address', TRUE)),
                    'phone' => htmlspecialchars($this->input->post('phone', TRUE)),
                    'postal_code' => htmlspecialchars($this->input->post('postal_code', TRUE)),
                    'province' => json_decode($this->input->post('province', TRUE), TRUE),
                    'city' => json_decode($this->input->post('city', TRUE), TRUE),
                    'district' => json_decode($this->input->post('district', TRUE), TRUE),
                    'courier' => json_decode($this->input->post('courier', TRUE), TRUE),
                    'unique_3digit' => $this->Transaction_model->generate_unique()
                ];

                $codCharge = $this->input->post('cash_on_delivery') == 'cod' ? 5000 : 0;

                $transaction = array(
                    'user_id' => $this->session->userdata('user')->id,
                    'snap_token' => $this->input->post('snap_token'),
                    'transaction_time' => $this->input->post('transaction_time'),
                    'transaction_status' => $this->input->post('transaction_status'),
                    'status_message' => $this->input->post('status_message'),
                    'status_code' => $this->input->post('status_code'),
                    'settlement_time' => $this->input->post('settlement_time'),
                    'payment_type' => $this->input->post('payment_type'),
                    'order_id' => $this->input->post('order_id'),
                    'amount' => (int) $this->input->post('amount') + (int) $this->input->post('unique_3digit') + (int) $codCharge,
                    'unique' => $params['unique_3digit'],
                    'fraud_status' => $this->input->post('fraud_status'),
                    'approval_code' => $this->input->post('approval_code'),
                    'cash_on_delivery' => $this->input->post('cash_on_delivery') == 'cod' ? true : false,
	                  'cash_on_delivery_markup' => $codCharge,
                    'description' => $this->input->post('description'),
                    'va_numbers' => $this->input->post('va_numbers'),
                    'payment_amounts' => $this->input->post('payment_amounts'),
                    'pdf_url' => $this->input->post('pdf_url'),
                    'finish_redirect_url' => $this->input->post('finish_redirect_url'),
                    'expired_time' => date("Ymdhis", strtotime("+30 minutes")),
                    'item_status' => 'waiting_transfer',
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s'),
                    'signature_key' => $this->input->post('signature_key'),
                );

                $orderId = time() + rand(1000, 9000);

                // Required
                $transaction_details = array(
                    'order_id' => $orderId,
                    'gross_amount' => 0, // no decimal allowed for creditcard
                );

                $transaction_details['gross_amount'] = (int) $params['courier']['cost']['value'];

                // Optional
                $item_details = [
                    [
                        'id' => 0,
                        'price' => (int) $transaction_details['gross_amount'],
                        'quantity' => 1,
                        'name' => 'Ongkos Kirim'
                    ]
                ];

                $transaction_details['gross_amount'] = (int) $transaction_details['gross_amount']  + (int) $params['unique_3digit'];

                $transactionDetails = [];

                $keyItem = 0;
                foreach($this->cart->contents() as $product) {
                    $keyItem++;
                    $find = $this->Product_model->findById($product['id']);
                    $item_details[$keyItem] = [
                        'id' => (int) $product['id'] + 1,
                        'price' => (int) $find->price,
                        'quantity' => $product['qty'],
                        'name' => $find->title
                    ];
    
                    $transaction_details['gross_amount'] = (int) $transaction_details['gross_amount'] + ((int) $item_details[$keyItem]['price'] * (int) $product['qty']);
                }

                $item_details[count($item_details)] = [
                    'id' => 100,
                    'price' => (int) $params['unique_3digit'],
                    'quantity' => 1,
                    'name' => 'Kode Unik 3 Digit'
                ];

                $transaction['amount'] = $transaction_details['gross_amount'];

                // Optional
                $billing_address = array(
                    'first_name'    => $params['recipient_name'],
                    'last_name'     => null,
                    'address'       => null,
                    'city'          => null,
                    'postal_code'   => $params['postal_code'],
                    'phone'         => $params['phone'],
                    'country_code'  => null
                );

                // Optional
                $shipping_address = array(
                    'first_name'    => $params['recipient_name'],
                    'last_name'     => '',
                    'address'       => $params['recipient_address'],
                    'city'          => $params['city']['city_name'],
                    'postal_code'   => $params['postal_code'] ?? $params['city']['postal_code'],
                    'phone'         => $params['phone'],
                    'country_code'  => 'IDN'
                );

                // Optional
                $customer_details = array(
                    'first_name'    => $params['recipient_name'],
                    'last_name'     => '',
                    'email'         => $this->session->userdata('user')->email,
                    'phone'         => $params['recipient_name'],
                    'billing_address'  => $billing_address,
                    'shipping_address' => $shipping_address
                );

                if($this->input->post('cash_on_delivery') == 'cash') {

                    $snapToken = $this->token($transaction_details, $item_details, $billing_address, $shipping_address, $customer_details);

                    if ($snapToken == null) {
                        return;
                    }

                    $transaction['snap_token'] = $snapToken;
                }
                $transaction['order_id'] = $transaction_details['order_id'];

                $affiliate = 0;
                $leaderId = 0;

                // cek afiliasi
                // if($dataAffiliate = get_cookie('aff_data')) {
                //     $checkUser = $this->User_model->get_user($dataAffiliate);

                //     if($checkUser && $dataAffiliate != $this->data['user']->id && $checkUser['role'] == 'affiliate') {
                //         $affiliate = $checkUser['id'];
                //         $leaderId = $checkUser['leader_id'];
                //     }
                // }
                
                $checkUser = $this->User_model->get_user($this->data['user']->id);
                
                if($checkUser && $checkUser['role'] == 'affiliate') {
                    $affiliate = $checkUser['id'];
                    $leaderId = $checkUser['leader_id'];
                } else {
                    if($dataAffiliate = get_cookie('aff_data')) {
                        $checkUserAffiliate = $this->User_model->get_user($dataAffiliate);
                        
                        if($checkUserAffiliate && $dataAffiliate != $this->data['user']->id && $checkUserAffiliate['role'] == 'affiliate') {
                            $affiliate = $checkUserAffiliate['id'];
                            $leaderId = $checkUserAffiliate['leader_id'];
                        }
                    }
                }

                $transaction['affiliate_id'] = $affiliate;
                $transaction['leader_id'] = $leaderId;

                $transaction_id = $this->Transaction_model->add_transaction($transaction);


                foreach($this->cart->contents() as $product) {
                    $find = $this->Product_model->findById($product['id']);
                    
                    $bonusCommisionMaintenance = $affiliate != 0 ? 0 : (int) ($find->commision_affiliator / 2) + ($find->commision_leader / 2);
                    $bonusCommisionProvider = $affiliate != 0 ? 0 : (int) ($find->commision_affiliator / 2) + ($find->commision_leader / 2);
                    $totalCommisionLeader = 0;
                    
		                if($affiliate != 0) {
			                $getAffiliator = $this->db->where('id', $affiliate)->get('users')->row();
			
			                if($getAffiliator) {
				
				                // kalo ada leader
				                if($getAffiliator->leader_id != 0) {
					                $totalCommisionLeader = ((int) $find->commision_leader * (int) $product['qty']);
				                }
			                }
		                }
		                
                    $transactionDetails[] = [
                        'transaction_id' => $transaction_id,
                        'affiliate_id' => $affiliate,
                        'product_id' => $product['id'],
                        'price' => $find->price,
                        'quantity' => $product['qty'],
                        'product' => json_encode([
                            'title' => $find->title,
                            'price' => $find->price,
                            'slug' => $find->slug,
                            'image' => str_replace(base_url(), '', $product['image'])
                        ]),
                        'total_commision_maintenance' => ((int) $find->commision_maintenance * (int) $product['qty']) + $bonusCommisionMaintenance,
                        'total_commision_affiliator' => $affiliate != 0 ? (int) $find->commision_affiliator * (int) $product['qty'] : 0,
                        'total_commision_provider' =>  ((int) $find->commision_provider * (int) $product['qty']) + $bonusCommisionProvider,
	                      'total_commision_mediator' =>  ((int) $find->commision_mediator * (int) $product['qty']),
	                      'total_commision_cs' =>  ((int) $find->commision_cs * (int) $product['qty']),
	                      'total_commision_leader' => $totalCommisionLeader,
                        'created_at' => date('Y-m-d'),
                        'updated_at' => date('Y-m-d H:i:s'),
                    ];
                    
                }
    
                $this->Transaction_detail_model->add_batch($transactionDetails);
    
                $transactionShipping = [
                    'transaction_id' => $transaction_id,
                    'first_name'    => $params['recipient_name'],
                    'last_name'     => '',
                    'address'       => $params['recipient_address'],
                    'email'       => $this->session->userdata('user')->email,
                    'city_name'          => $params['city']['city_name'],
                    'city_id'          => $params['city']['city_id'],
                    'district_name'          => $params['district']['subdistrict_name'],
                    'district_id'          => $params['district']['subdistrict_id'],
                    'province'          => $params['province']['province'],
                    'province_id'          => $params['province']['province_id'],
                    'postal_code'   => $params['postal_code'] ?? $params['city']['postal_code'],
                    'phone'         => $params['phone'],
                    'courier'  => $params['courier']['code'],
                    'service'  => $params['courier']['service'],
                    'courier_desc'  => $params['courier']['label'],
                    'courier_json' => json_encode($params['courier']),
                    'cost'  => $params['courier']['cost']['value'],
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s'),
                ];
    
                $this->Transaction_shipping_model->add_transaction($transactionShipping);
    
                $this->db->trans_complete();
    
                if ($this->db->trans_status() === FALSE)
                {
                    $this->db->trans_rollback();
                    return toJson([
                        'success' => false,
                        'data' => null
                    ]);
                }
                else
                {
                    $this->db->trans_commit();
                    foreach($this->cart->contents() as $items) {
                        $this->cart->update([
                            'rowid' => $items['rowid'],
                            'qty' => 0,
                        ]);
                    }

                    return toJson([
                        'success' => true,
                        'data' => $transaction
                    ]);
                }
    
                return toJson([
                    'success' => true,
                    'data' => $transaction
                ]);
            }
        } catch (Exception $e) {
            
        }
    }

    /*
     * Adding a new transaction
     */
    function add()
    {   
        if(isset($_POST) > 0)     
        {   
            $this->db->trans_start();

            $params = array(
				'user_id' => $this->_authUser->id,
				'snap_token' => $this->input->post('snap_token'),
				'transaction_time' => $this->input->post('transaction_time'),
				'transaction_status' => $this->input->post('transaction_status'),
				'status_message' => $this->input->post('status_message'),
				'status_code' => $this->input->post('status_code'),
				'settlement_time' => $this->input->post('settlement_time'),
				'payment_type' => $this->input->post('payment_type'),
				'order_id' => $this->input->post('order_id'),
				'amount' => $this->input->post('amount'),
				'fraud_status' => $this->input->post('fraud_status'),
				'approval_code' => $this->input->post('approval_code'),
				'description' => $this->input->post('description'),
				'va_numbers' => $this->input->post('va_numbers'),
				'payment_amounts' => $this->input->post('payment_amounts'),
				'pdf_url' => $this->input->post('pdf_url'),
				'finish_redirect_url' => $this->input->post('finish_redirect_url'),
				'expired_time' => $this->input->post('expired_time'),
				'item_status' => 'waiting_transfer',
				'created_at' => date('Y-m-d H:i:s'),
				'updated_at' => date('Y-m-d H:i:s'),
				'signature_key' => $this->input->post('signature_key'),
            );

            $orderId = time() + rand() + (int) inputPost('user_id');

            // Required
            $transaction_details = array(
                'order_id' => $orderId,
                'gross_amount' => 0, // no decimal allowed for creditcard
            );

            $transaction_details['gross_amount'] = (int) inputPost('shipping')['courier']['cost']['value'];

            // Optional
            $item_details = [
                [
                    'id' => 0,
                    'price' => (int) $transaction_details['gross_amount'],
                    'quantity' => 1,
                    'name' => 'Ongkos Kirim'
                ]
            ];
            $transactionDetails = [];

            foreach(inputPost('products') as $key => $product) {
                $find = $this->Product_model->findById($product['id']);
                $item_details[$key+1] = [
                    'id' => $product['id'],
                    'price' => (int) $find->price,
                    'quantity' => $product['quantity'],
                    'name' => $find->title
                ];

                $transaction_details['gross_amount'] = (int) $transaction_details['gross_amount'] + ((int) $item_details[$key+1]['price'] * (int) $product['quantity']);
            }

            $params['amount'] = $transaction_details['gross_amount'];

            // Optional
            $billing_address = array(
                'first_name'    => inputPost('contact')['first_name'],
                'last_name'     => inputPost('contact')['last_name'],
                'address'       => null,
                'city'          => null,
                'postal_code'   => null,
                'phone'         => inputPost('contact')['phone'],
                'country_code'  => null
            );

            // Optional
            $shipping_address = array(
                'first_name'    => inputPost('shipping')['first_name'],
                'last_name'     => inputPost('shipping')['last_name'],
                'address'       => inputPost('shipping')['address'],
                'city'          => inputPost('shipping')['city']['city_name'],
                'postal_code'   => inputPost('shipping')['city']['postal_code'],
                'phone'         => inputPost('shipping')['phone'],
                'country_code'  => 'IDN'
            );

            // Optional
            $customer_details = array(
                'first_name'    => inputPost('contact')['first_name'],
                'last_name'     => inputPost('contact')['last_name'],
                'email'         => inputPost('contact')['email'],
                'phone'         => inputPost('contact')['phone'],
                'billing_address'  => $billing_address,
                'shipping_address' => $shipping_address
            );

            $snapToken = $this->token($transaction_details, $item_details, $billing_address, $shipping_address, $customer_details);

            if($snapToken == null) {
                return;
            }

            $params['snap_token'] = $snapToken;
            $params['order_id'] = $transaction_details['order_id'];

            $transaction_id = $this->Transaction_model->add_transaction($params);

            foreach(inputPost('products') as $key => $product) {
                $transactionDetails[$key] = [
                    'transaction_id' => $transaction_id,
                    'product_id' => $product['id'],
                    'price' => $find->price,
                    'quantity' => $product['quantity'],
                ];

            }

            $this->Transaction_detail_model->add_batch($transactionDetails);

            $transactionShipping = [
                'transaction_id' => $transaction_id,
                'first_name'    => inputPost('shipping')['first_name'],
                'last_name'     => inputPost('shipping')['last_name'],
                'address'       => inputPost('shipping')['address'],
                'email'       => inputPost('shipping')['email'],
                'city_name'          => inputPost('shipping')['city']['city_name'],
                'city_id'          => inputPost('shipping')['city']['city_id'],
                'province'          => inputPost('shipping')['province']['province'],
                'province_id'          => inputPost('shipping')['province']['province_id'],
                'postal_code'   => inputPost('shipping')['city']['postal_code'],
                'phone'         => inputPost('shipping')['phone'],
                'courier'  => inputPost('shipping')['courier']['service'],
                'courier_desc'  => inputPost('shipping')['courier']['label'],
                'cost'  => inputPost('shipping')['courier']['cost']['value'],
                'created_at' => date('Y-m-d H:i:s'),
				'updated_at' => date('Y-m-d H:i:s'),
            ];

            $this->Transaction_shipping_model->add_transaction($transactionShipping);

            $this->db->trans_complete();

            if ($this->db->trans_status() === FALSE)
            {
                $this->db->trans_rollback();
                return toJson([
                    'success' => false,
                    'data' => null
                ]);
            }
            else
            {
                $this->db->trans_commit();
                return toJson([
                    'success' => true,
                    'data' => $params
                ]);
            }

            return toJson([
                'success' => true,
                'data' => $params
            ]);
        }
        else
        {
			return toJson([
                'success' => false,
                'data' => null
            ]);
        }
    }  

    public function notification () {
        try {
            $this->db->trans_start();

            $notif = json_decode(file_get_contents("php://input"), true);
            $transaction = $notif['transaction_status'];
            $type = $notif['payment_type'];
            $order_id = $notif['order_id'];
            $fraud = isset($notif['fraud_status']) ? $notif['fraud_status'] : '';
            $description = '';
            if ($transaction == 'capture') {
                // For credit card transaction, we need to check whether transaction is challenge by FDS or not
                if ($type == 'credit_card'){
                    if($fraud == 'challenge'){
                        // TODO set payment status in merchant's database to 'Challenge by FDS'
                        // TODO merchant should decide whether this transaction is authorized or not in MAP
                        $description =  "Transaction order_id: " . $order_id ." is challenged by FDS";
                    } 
                    else {
                        // TODO set payment status in merchant's database to 'Success'
                        $description =  "Transaction order_id: " . $order_id ." successfully captured using " . $type;
                    }
                }
            } else if ($transaction == 'settlement'){
                // TODO set payment status in merchant's database to 'Settlement'
                $description =  "Transaction order_id: " . $order_id ." successfully transfered using " . $type;
                } 
                else if($transaction == 'pending'){
                // TODO set payment status in merchant's database to 'Pending'
                $description =  "Waiting customer to finish transaction order_id: " . $order_id . " using " . $type;
                } 
                else if ($transaction == 'deny') {
                // TODO set payment status in merchant's database to 'Denied'
                $description =  "Payment using " . $type . " for transaction order_id: " . $order_id . " is denied.";
                }
                else if ($transaction == 'expire') {
                // TODO set payment status in merchant's database to 'expire'
                $description =  "Payment using " . $type . " for transaction order_id: " . $order_id . " is expired.";
                }
                else if ($transaction == 'cancel') {
                // TODO set payment status in merchant's database to 'Denied'
                $description =  "Payment using " . $type . " for transaction order_id: " . $order_id . " is canceled.";
            }

            $transaction = [
                'description' => $description,
                'transaction_time' => $notif['transaction_time'],
                'transaction_status' => $notif['transaction_status'],
                // 'transaction_id' => $notif['transaction_id'],
                'status_message' => $notif['status_message'],
                'status_code' => $notif['status_code'],
                'signature_key' => $notif['signature_key'],
                'settlement_time' => isset($notif['settlement_time']) ? $notif['settlement_time'] : '',
                'payment_type' => $notif['payment_type'],
                'fraud_status' => isset($notif['fraud_status']) ? $notif['fraud_status'] : '',
                'approval_code' => isset($notif['approval_code']) ? $notif['approval_code'] : '',
                'item_status' => $notif['transaction_status'] == 'settlement' ? 'pending' : 'waiting_transfer',
                // 'referer_host' => parse_url($_SERVER['REMOTE_ADDR'], PHP_URL_HOST) ?? ''
            ];
            if(isset($notif['payment_amounts'])) {
                $transaction['payment_amounts'] = json_encode($notif['payment_amounts']);
            }

            $dataTransaction = $this->Transaction_model->findByOrderId($order_id);
            $this->Transaction_model->update_transaction($dataTransaction->id, $transaction);

            if($notif['transaction_status'] == 'settlement') {
                $this->Commision_model->generate_commision_transaction($dataTransaction->id);
                $this->Transaction_detail_model->updateByTransaction($dataTransaction->id,[
                    'delivery_status' => 'process'
                ]);

                $transactionDetail = $this->Transaction_model->findByOrderId($order_id);

                $this->Notification_model->add_notification([
                    'user_id' => $transactionDetail->user_id,
                    'content' => "Pembayaran <strong>{$transactionDetail->order_id}</strong> Diterima",
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s'),
                ]);
            }
            
            
            $this->db->trans_complete();
            if ($this->db->trans_status() === FALSE){
                $this->db->trans_rollback();
            }else{
                $this->db->trans_commit();
            }        
        } catch (Exception $e) {
            
        }
    }

    public function callback_cek_mutasi()
    {
        try {
            $this->db->trans_start();

            $cekmutasi = array(
                "api_signature" => "eHON81sv0btOHnlv1ozijvF3q8GNZ7Fu"
            );

            $incomingApiSignature = isset($_SERVER['HTTP_API_SIGNATURE']) ? $_SERVER['HTTP_API_SIGNATURE'] : '';

            if( !hash_equals($cekmutasi['api_signature'], $incomingApiSignature) ) {
                exit("Invalid Signature");
            }

            $post = file_get_contents("php://input");
            $json = json_decode($post);

            if( json_last_error() !== JSON_ERROR_NONE ) {
                exit("Invalid JSON");
            }

            if( $json->action == "payment_report" ) {
                foreach( $json->content->data as $data ) {
                    $type = $data->type;
                    $amount = str_replace(".00","", $data->amount);
                    $description = $data->description;

                    if( $type == "credit" ) {
                        $check = $this->db
                            ->where('amount', $amount)
                            ->where('item_status', 'waiting_transfer')
                            ->get('transactions')
                            ->row();

                        if($check) {
                            $this->db->where('id', $check->id)->update('transactions', ['item_status' => 'process']);
                            //$this->Commision_model->generate_commision_transaction($check->id);
                            $this->Transaction_detail_model->updateByTransaction($check->id,[
                                'delivery_status' => 'process'
                            ]);

                            $transactionDetail = $this->Transaction_model->findByOrderId($check->order_id);

                            $this->Notification_model->add_notification([
                                'user_id' => $transactionDetail->user_id,
                                'content' => "Pembayaran <strong>{$transactionDetail->order_id}</strong> Diterima",
                                'created_at' => date('Y-m-d H:i:s'),
                                'updated_at' => date('Y-m-d H:i:s'),
                            ]);
                        }
                    }
                }
            }

            $this->db->trans_complete();
            if ($this->db->trans_status() === FALSE){
                $this->db->trans_rollback();
            }else{
                $this->db->trans_commit();
            }

        } catch (Exception $e) {

        }
    }

    public function token($transaction_details, $item_details, $billing_address, $shipping_address, $customer_details)
    {
        // Data yang akan dikirim untuk request redirect_url.
        $credit_card['secure'] = true;
        //ser save_card true to enable oneclick or 2click
        //$credit_card['save_card'] = true;

        $time = time();
        $custom_expiry = array(
            'start_time' => date("Y-m-d H:i:s O",$time),
            'unit' => 'minute', 
            'duration'  => 30
        );
        
        $transaction_data = array(
            'transaction_details'=> $transaction_details,
            'item_details'       => $item_details,
            'customer_details'   => $customer_details,
            'credit_card'        => $credit_card,
            'expiry'             => $custom_expiry
        );

        $snapToken = $this->midtrans->getSnapToken($transaction_data);
        return $snapToken ?? null;
}

    /*
     * Editing a transaction
     */
    function edit($id)
    {   
        // check if the transaction exists before trying to edit it
        $data['transaction'] = $this->Transaction_model->get_transaction($id);
        
        if(isset($data['transaction']['id']))
        {
            if(isset($_POST) && count($_POST) > 0)     
            {   
                $params = array(
					'user_id' => $this->input->post('user_id'),
					'product_id' => $this->input->post('product_id'),
					'snap_token' => $this->input->post('snap_token'),
					'transaction_time' => $this->input->post('transaction_time'),
					'transaction_status' => $this->input->post('transaction_status'),
					'status_message' => $this->input->post('status_message'),
					'status_code' => $this->input->post('status_code'),
					'settlement_time' => $this->input->post('settlement_time'),
					'payment_type' => $this->input->post('payment_type'),
					'order_id' => $this->input->post('order_id'),
					'amount' => $this->input->post('amount'),
					'fraud_status' => $this->input->post('fraud_status'),
					'approval_code' => $this->input->post('approval_code'),
					'description' => $this->input->post('description'),
					'va_numbers' => $this->input->post('va_numbers'),
					'payment_amounts' => $this->input->post('payment_amounts'),
					'pdf_url' => $this->input->post('pdf_url'),
					'finish_redirect_url' => $this->input->post('finish_redirect_url'),
					'expired_time' => $this->input->post('expired_time'),
					'item_status' => $this->input->post('item_status'),
					'created_at' => $this->input->post('created_at'),
					'updated_at' => $this->input->post('updated_at'),
					'signature_key' => $this->input->post('signature_key'),
                );

                $this->Transaction_model->update_transaction($id,$params);            
                return toJson([
                    'success' => true,
                    'data' => null
                ]);
            }
            else
            {
				return toJson([
                    'success' => false,
                    'data' => null
                ]);
            }
        }
        else
            show_error('The transaction you are trying to edit does not exist.');
    } 

    /*
     * Deleting transaction
     */
    function remove($id)
    {
        $transaction = $this->Transaction_model->get_transaction($id);

        // check if the transaction exists before trying to delete it
        if(isset($transaction['id']))
        {
            $this->Transaction_model->delete_transaction($id);
            redirect('transaction/index');
        }
        else
            show_error('The transaction you are trying to delete does not exist.');
    }
    
}
