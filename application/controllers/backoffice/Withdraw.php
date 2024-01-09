<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Backoffice_Controller.php';

class Withdraw extends Backoffice_Controller {
  public function __construct()
  {
    parent::__construct();
    $this->load->model('Widthdraw_affiliate_model');
    $this->load->model('Withdraw_provider_maintenance_model');
    $this->load->model('Commision_model');
  }

  public function datatable()
  {
    header('Content-Type: application/json');
    echo $this->Widthdraw_affiliate_model->datatable();
  }

  public function provider_history()
  {
    header('Content-Type: application/json');
    echo $this->Withdraw_provider_maintenance_model->provider();
  }

  public function maintenance_history()
  {
    header('Content-Type: application/json');
    echo $this->Withdraw_provider_maintenance_model->maintenance();
  }

  public function leader_history()
  {
    header('Content-Type: application/json');
    echo $this->Withdraw_provider_maintenance_model->leader();
  }

  public function mediator_history()
  {
    header('Content-Type: application/json');
    echo $this->Withdraw_provider_maintenance_model->mediator();
  }

  public function cs_history()
  {
    header('Content-Type: application/json');
    echo $this->Withdraw_provider_maintenance_model->cs();
  }

  public function index()
	{
    $this->data['page_title'] = 'Penarikan';
    $this->data['page'] = 'backoffice/withdraw/index';

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Penarikan',
        'link' => 1
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

	public function downloadlaporantransaksi()
	{
		set_include_path(APPPATH . 'third_party/PHPExcel/Classes/');
		include 'PHPExcel/IOFactory.php';
		$objPHPExcel = new PHPExcel();
		$idtarif = $this->db->query("select a.id as no, c.first_name , 
		c.last_name, c.email, c.phone ,a.order_id , a.amount ,a.item_status,
		 a.created_at,b.quantity,b.delivery_status,d.title from transactions a 
		 join transaction_details b on a.id = b.transaction_id join users c
		 on a.user_id = c.id join products d on b.product_id = d.id")->result_array();
		$data = $idtarif;
		$no = 1;
		$row = 2;
		if (count($data) > 0) {
			if ($data) {
			
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('A1', 'No');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('B1', 'Nama Depan');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('C1', 'Belakang');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('D1', 'Email');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('E1', 'Telephone');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('F1', 'Order Id');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('G1', 'Total Belanja');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('H1', 'Status Pengiriman');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('I1', 'Tanggal Pembuatan');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('J1', 'Nama Barang');
					$objPHPExcel->setActiveSheetIndex(0)->setCellValue('K1', 'Jumlah Item');

				foreach ($data as $dataExcel) {
	
					$objPHPExcel->getActiveSheet(0)->getStyle('A' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('A' . $row, $dataExcel['no'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('A')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('B' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('B' . $row, $dataExcel['first_name'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('B')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('C' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('C' . $row, $dataExcel['last_name'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('C')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('D' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('D' . $row, $dataExcel['email'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('D')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('E' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('E' . $row, $dataExcel['phone'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('E')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('F' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('F' . $row, $dataExcel['order_id'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('F')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('G' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('G' . $row, $dataExcel['amount'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('G')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('H' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('H' . $row, $dataExcel['delivery_status'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('H')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('I' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('I' . $row, $dataExcel['created_at'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('I')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('J' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('J' . $row, $dataExcel['title'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('J')->setAutoSize(true);

					$objPHPExcel->getActiveSheet(0)->getStyle('K' . $row)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_TEXT);
					$objPHPExcel->getActiveSheet(0)->setCellValueExplicit('K' . $row, $dataExcel['quantity'], PHPExcel_Cell_DataType::TYPE_STRING);
					$objPHPExcel->getActiveSheet(0)->getColumnDimension('K')->setAutoSize(true);

					$row++;
					$no++;
				}
				header('Content-Type: application/vnd.ms-excel; charset=utf-8');
				header('Content-Disposition: attachment; filename=exporttransaksi.xls');
				header('Cache-Control: max-age=0');
				ob_end_clean();
				ob_start();
				$objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, 'Excel5');
				$filename = 'Sample' . 'csv';
				$objWriter->save('php://output');
			}
		}
	}
	
  public function mediator()
	{
    $this->data['page_title'] = 'Penarikan Mediator';
    $this->data['page'] = 'backoffice/withdraw/mediator';
    $this->data['saldo'] = $this->Commision_model->get_total_commision_mediator();
    $this->data['earning_today'] = $this->Commision_model->get_earning_today_mediator();
    $this->data['earning_month'] = $this->Commision_model->get_earning_month_mediator();
    $this->data['earning_month_yesterday'] = $this->Commision_model->get_earning_month_yesterday_mediator();

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Penarikan',
        'link' => 1
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function mediator_process()
  {
    try {
      if(isset($_POST) > 0) {
        $this->db->trans_start();

        $this->data['saldo'] = $this->Commision_model->get_total_commision_mediator();

        if((int) $this->data['saldo'] <= 0) {
          $this->session->set_flashdata('err', 'Gagal Mencairkan Dana');
          return redirect(base_url('backoffice/withdraw/mediator'));
        }

        $this->Withdraw_provider_maintenance_model->add([
          'amount' => $this->data['saldo'],
          'type' => 'mediator',
          'created_at' => date('Y-m-d H:i:s'),
          'updated_at' => date('Y-m-d H:i:s'),
        ]);

        $this->db->set('amount', "amount-{$this->data['saldo']}", FALSE);
        $this->db->update('mediator_commision');

        $this->db->trans_complete();

        if ($this->db->trans_status() === FALSE) {
          $this->db->trans_rollback();
          $this->session->set_flashdata('err', 'Gagal Mencairkan Dana');
          return redirect(base_url('backoffice/withdraw/mediator'));
        } else {
          $this->db->trans_commit();
          $this->session->set_flashdata('success', 'Berhasil Mencairkan Dana');
          return redirect(base_url('backoffice/withdraw/mediator'));
        }
      }
    } catch (Exception $e) {
      $this->session->set_flashdata('err', 'Gagal Mencairkan Dana');
      return redirect(base_url('backoffice/withdraw/mediator'));
    }
  }

  public function cs()
	{
    $this->data['page_title'] = 'Penarikan CS';
    $this->data['page'] = 'backoffice/withdraw/cs';
    $this->data['saldo'] = $this->Commision_model->get_total_commision_cs();
    $this->data['earning_today'] = $this->Commision_model->get_earning_today_cs();
    $this->data['earning_month'] = $this->Commision_model->get_earning_month_cs();
    $this->data['earning_month_yesterday'] = $this->Commision_model->get_earning_month_yesterday_cs();

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Penarikan',
        'link' => 1
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function cs_process()
  {
    try {
      if(isset($_POST) > 0) {
        $this->db->trans_start();

        $this->data['saldo'] = $this->Commision_model->get_total_commision_cs();

        if((int) $this->data['saldo'] <= 0) {
          $this->session->set_flashdata('err', 'Gagal Mencairkan Dana');
          return redirect(base_url('backoffice/withdraw/cs'));
        }

        $this->Withdraw_provider_maintenance_model->add([
          'amount' => $this->data['saldo'],
          'type' => 'cs',
          'created_at' => date('Y-m-d H:i:s'),
          'updated_at' => date('Y-m-d H:i:s'),
        ]);

        $this->db->set('amount', "amount-{$this->data['saldo']}", FALSE);
        $this->db->update('cs_commision');

        $this->db->trans_complete();

        if ($this->db->trans_status() === FALSE) {
          $this->db->trans_rollback();
          $this->session->set_flashdata('err', 'Gagal Mencairkan Dana');
          return redirect(base_url('backoffice/withdraw/cs'));
        } else {
          $this->db->trans_commit();
          $this->session->set_flashdata('success', 'Berhasil Mencairkan Dana');
          return redirect(base_url('backoffice/withdraw/cs'));
        }
      }
    } catch (Exception $e) {
      $this->session->set_flashdata('err', 'Gagal Mencairkan Dana');
      return redirect(base_url('backoffice/withdraw/cs'));
    }
  }

  public function maintenance()
	{
    $this->data['page_title'] = 'Penarikan Maintenance';
    $this->data['page'] = 'backoffice/withdraw/maintenance';
    $this->data['saldo'] = $this->Commision_model->get_total_commision_maintenance();
    $this->data['earning_today'] = $this->Commision_model->get_earning_today_maintenance();
    $this->data['earning_month'] = $this->Commision_model->get_earning_month_maintenance();
    $this->data['earning_month_yesterday'] = $this->Commision_model->get_earning_month_yesterday_maintenance();

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Penarikan',
        'link' => 1
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function maintenance_process()
  {
    try {
      if(isset($_POST) > 0) {
        $this->db->trans_start();

        $this->data['saldo'] = $this->Commision_model->get_total_commision_maintenance();

        if((int) $this->data['saldo'] <= 0) {
          $this->session->set_flashdata('err', 'Gagal Mencairkan Dana');
          return redirect(base_url('backoffice/withdraw/maintenance'));
        }

        $this->Withdraw_provider_maintenance_model->add([
          'amount' => $this->data['saldo'],
          'type' => 'maintenance',
          'created_at' => date('Y-m-d H:i:s'),
          'updated_at' => date('Y-m-d H:i:s'),
        ]);

        $this->db->set('amount', "amount-{$this->data['saldo']}", FALSE);
        $this->db->update('maintenance_commision');

        $this->db->trans_complete();

        if ($this->db->trans_status() === FALSE) {
          $this->db->trans_rollback();
          $this->session->set_flashdata('err', 'Gagal Mencairkan Dana');
          return redirect(base_url('backoffice/withdraw/maintenance'));
        } else {
          $this->db->trans_commit();
          $this->session->set_flashdata('success', 'Berhasil Mencairkan Dana');
          return redirect(base_url('backoffice/withdraw/maintenance'));
        }
      }
    } catch (Exception $e) {
      $this->session->set_flashdata('err', 'Gagal Mencairkan Dana');
      return redirect(base_url('backoffice/withdraw/maintenance'));
    }
  }

  public function provider_process()
  {
    try {
      if(isset($_POST) > 0) {
        $this->db->trans_start();

        $this->data['saldo'] = $this->Commision_model->get_total_commision_provider();

        if((int) $this->data['saldo'] <= 0) {
          $this->session->set_flashdata('err', 'Gagal Mencairkan Dana');
          return redirect(base_url('backoffice/withdraw/provider'));
        }

        $this->Withdraw_provider_maintenance_model->add([
          'amount' => $this->data['saldo'],
          'type' => 'provider',
          'created_at' => date('Y-m-d H:i:s'),
          'updated_at' => date('Y-m-d H:i:s'),
        ]);

        $this->db->set('amount', "amount-{$this->data['saldo']}", FALSE);
        $this->db->update('provider_commision');

        $this->db->trans_complete();

        if ($this->db->trans_status() === FALSE) {
          $this->db->trans_rollback();
          $this->session->set_flashdata('err', 'Gagal Mencairkan Dana');
          return redirect(base_url('backoffice/withdraw/provider'));
        } else {
          $this->db->trans_commit();
          $this->session->set_flashdata('success', 'Berhasil Mencairkan Dana');
          return redirect(base_url('backoffice/withdraw/provider'));
        }
      }
    } catch (Exception $e) {
      $this->session->set_flashdata('err', 'Gagal Mencairkan Dana');
      return redirect(base_url('backoffice/withdraw/provider'));
    }
  }

  public function provider()
	{
    $this->data['page_title'] = 'Penarikan Provider';
    $this->data['page'] = 'backoffice/withdraw/provider';
    $this->data['saldo'] = $this->Commision_model->get_total_commision_provider();
    $this->data['earning_today'] = $this->Commision_model->get_earning_today_provider();
    $this->data['earning_month'] = $this->Commision_model->get_earning_month_provider();
    $this->data['earning_month_yesterday'] = $this->Commision_model->get_earning_month_yesterday_provider();

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Penarikan',
        'link' => 1
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function detail($id = 0)
	{
    $this->data['page_title'] = 'Detail Penarikan';
    $this->data['page'] = 'backoffice/withdraw/detail';

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Penarikan',
        'link' => 1
      ]
    ];

    $this->data['detail'] = $this->Widthdraw_affiliate_model->detail_with_user($id);

		$this->load->view('backoffice/index', $this->data);
  }

  public function update_status($id = 0)
  {
    try {

      $update  = $this->Widthdraw_affiliate_model->update_withdraw_affiliate($id, [
        'status' => $this->input->post('status') ?? 'pending'
      ]);

      if(!$update) {
        $this->session->set_flashdata('err', 'Gagal Update Status');
        return redirect(base_url('backoffice/withdraw/detail/' . $id));
      }

      $this->session->set_flashdata('success', 'Sukses Update Status');
      return redirect(base_url('backoffice/withdraw/detail/' . $id));
    } catch (Exception $e) {
      $this->session->set_flashdata('err', 'Gagal Update Status');
      return redirect(base_url('backoffice/withdraw/detail/' . $id));
    }
  }
}
