import copy
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import release_bundle as r


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup); self.root=Path(self.tmp.name).resolve()
        self.inputs={}; self.betas={}; self.units={}; self.transports={}
        decision=self.root/'decision.json'; decision.write_bytes((r.ROOT/'evidence/d14-publisher-decision.json').read_bytes())
        cert=self.root/'certificate.pem'; cert.write_bytes(b'fixture-public-certificate')
        self.certpin=r.c.sha(cert.read_bytes()); policy=self.root/'policy.json'; policy.write_text('{}')
        self.request={'protocol':r.REQUEST,'release':r.signing.RELEASE,'profiles':{},'publisher_decision':{'path':str(decision),'sha256':r.signing.DECISION},
            'public_certificate':{'path':str(cert),'sha256':self.certpin},'privacy_policy':str(policy),'additional_documents':[]}
        for profile,subdir in r.publisher.PROFILES.items(): self.make_profile(profile,subdir)
        self.make_pkg()
        self.request_path=self.root/'request.json'; self.save_request()
    def save_request(self):
        self.request_path.write_bytes(r.fs.canonical(self.request)); self.request_sha=r.c.sha(self.request_path.read_bytes())
    def write(self,path,value):
        path.parent.mkdir(parents=True,exist_ok=True)
        data=value if isinstance(value,bytes) else r.fs.canonical(value); path.write_bytes(data); return r.c.sha(data)
    def selected(self,profile,role,folder,record,path):
        digest=self.write(folder/path,record)
        row={'workflow_commit':'a'*40,'result_sha256':digest}
        proof={'selection_sha256':'b'*64,'selection':{'profile':profile,'artifacts':{role:row}},'github_observation':{'conclusion':'success'}}
        self.transports[profile,role]=(folder,record,proof)
        return {'root':str(folder.parents[1]),'selection':str(self.root/(profile+'-'+role+'.json')),'selection_sha256':'b'*64}
    def make_profile(self,profile,subdir):
        root=self.root/profile/'beta/artifacts/beta'; root.mkdir(parents=True)
        entries=[]; archives=[]; observations=[]
        for number in range(59):
            kind='native_receipt_unit' if number<51 else 'go_command' if number<57 else 'external_inert_runtime_and_sdk' if number==57 else 'client_bridge_bundle'
            component=f'unit{number:02}'; entry={'component_id':component,'native_version':'1.0.0','kind':kind}; entries.append(entry)
            name='symphony-'+component+'-payload'; build=profile.replace('.','_')+'_1'; filename=f'{name}-1.0.0-{build}.conda'
            data=(profile+component).encode(); row={'name':name,'version':'1.0.0','build':build,'build_number':1,'subdir':subdir,'filename':filename,'sha256':r.c.sha(data),'size':len(data)}
            archives.append(row); self.write(root/'carriers/channel'/subdir/filename,data)
            if number<51:
                digest=r.c.sha(component.encode())
                self.units[component]={'files':[{'path':f'share/symphony/receipts/{component}/1.0.0/install-receipt.json','sha256':digest}]}
                observations.append({'component_id':component,'version':'1.0.0','receipt_sha256':digest,**{k:True for k in r.UNIT_PASS}})
        cohort={'entries':entries,'archives':archives,'cohort_digest':'sha256:'+r.c.sha(profile.encode()),'conda_subdir':subdir}
        optional=copy.deepcopy(archives[0]); optional.update(name='symphony-source-payload',filename=f'symphony-source-payload-1.0.0-{profile.replace(".","_")}_0.conda',build=profile.replace('.','_')+'_0')
        self.write(root/'source/carrier/channel'/subdir/optional['filename'],(profile+'unit00').encode())
        optional_doc=r.c.sealed({'archives':[optional],'base_carrier_cohort_digest':cohort['cohort_digest']})
        self.write(root/'source/carrier/cohort.json',optional_doc)
        wrappers=[]
        for form in (['sh','pkg'] if profile=='macos15-arm64' else ['sh']):
            data=(profile+form).encode(); filename='Symphony-0.2.0-beta.1.'+form
            self.write(root/'wrappers'/filename,data); wrappers.append({'format':form,'filename':filename,'size':len(data),'sha256':r.c.sha(data)})
        wrapper={'wrappers':wrappers,'retention_index_sha256':r.c.sha(b'index'),'retention_helper_sha256':r.c.sha(b'script')}
        wrapper_sha=self.write(root/'wrappers/result.json',wrapper)
        for name,data in [('symphony-retain.py',b'script'),('BOOTSTRAP-INDEX.json',b'index'),('COHORT.json',b'cohort')]: self.write(root/'setup'/name,data)
        source=b'exact reviewed source'; self.write(root/'source/source.tar',source)
        source_sha=self.write(root/'source/source-index.json',{'archive':{'filename':'source.tar','sha256':r.c.sha(source),'size':len(source)}})
        client_sha=self.write(root/'provenance/client/result.json',{'state':'client-qualified','actual_codex_cases':22})
        journey_sha=self.write(root/'provenance/carrier-journeys.json',{'state':'journeys-qualified','transaction_count':182})
        lineage={k:profile if k=='profile' else 'f'*64 for k in r.LINEAGE}
        beta={'profile':profile,'publisher_decision_sha256':r.signing.DECISION,'original_native_lineage':lineage,
            'shell_qualification':{'state':'installed_refusals_and_named_removal_passed'},
            'retention_qualification':{'state':'installed_retention_and_read_only_entrypoints_passed','retained_after_carrier_removal':True},
            'cohort_sha256':'c'*64,'optional_source_cohort_digest':optional_doc['cohort_digest'],'wrappers_result_sha256':wrapper_sha,'source_index_sha256':source_sha,
            'input_artifacts':{'client':{'result_sha256':client_sha}},'carrier_journeys_sha256':journey_sha,'client_sources':{'commit':'d'*40}}
        self.request['profiles'][profile]={'beta':self.selected(profile,'beta',root,beta,'result.json')}
        maintained={'protocol':'symphony.distribution.retained-native-maintenance.v1','state':'primary_retained_native_disposable_owner_campaign_passed',
            'profile':profile,'native_unit_count':51,'retained_payload_unchanged':True,'original_artifacts_unchanged':True,'caller_state_preserved':True,
            'lineage':lineage,'qualification_toolkit':{'commit':'a'*40},'units':observations}
        maintroot=self.root/profile/'maintenance/artifacts/maintenance'
        self.request['profiles'][profile]['maintenance']=self.selected(profile,'maintenance',maintroot,maintained,'d13-maintenance/result.json')
        self.betas[profile]=(beta,cohort,wrappers[0])
    def make_pkg(self):
        beta,cohort,_=self.betas['macos15-arm64']; base=self.transports['macos15-arm64','beta'][0]
        wrapper=json.loads((base/'wrappers/result.json').read_bytes()); pkg=wrapper['wrappers'][1]
        record={'protocol':'symphony.distribution.native-pkg-qualification.v1','state':'native_pkg_install_and_named_carrier_removal_passed',
            'profile':'macos15-arm64','carrier_count':59,'linked_file_count':177,'pkg_sha256':pkg['sha256'],'cohort_digest':cohort['cohort_digest'],
            'cohort_sha256':beta['cohort_sha256'],'wrapper_result_sha256':beta['wrappers_result_sha256'],'executing_toolkit':{'commit':'a'*40},
            **{k:True for k in ('native_pkg_executed','all_named_carriers_removed','caller_configuration_preserved','user_and_outside_sentinels_preserved','wrapper_support_files_preserved','original_inputs_unchanged')},
            **{k:False for k in ('system_trust_changed','gatekeeper_bypassed','apple_developer_id','notarized')}}
        folder=self.root/'pkg/artifacts/native_pkg'; self.request['native_pkg']=self.selected('macos15-arm64','native_pkg',folder,record,'d14-pkg-public/result.json')
    def assemble(self):
        scanner=types.SimpleNamespace(configure_policy=lambda _:None,scan=lambda name,data:None)
        def admit(value,role,profile): return self.transports[profile,role]
        def beta_admit(path,pin): return self.betas[path.parents[2].name]
        with patch.object(r,'admit_transport',side_effect=admit),patch.object(r.assembler,'admit_candidate',side_effect=beta_admit),\
             patch.object(r.c,'validate_recipe',side_effect=lambda root,e:(self.units[e['component_id']],{})),\
             patch.object(r.c,'load_module',return_value=scanner),patch.object(r.signing,'certificate'),\
             patch.object(r.verifier,'CERTIFICATE_SHA256',self.certpin):
            return r.assemble(self.request_path,self.request_sha,self.root/'release',Path('/openssl'))
    def test_complete_bundle_copies_exact_packages_evidence_and_explicit_modular_urls(self):
        result=self.assemble(); out=self.root/'release'
        self.assertEqual(len(result['conda_packages']),240); self.assertEqual(len(result['profiles']),4)
        self.assertLess(len(result['artifacts'])+1,1024); self.assertIn('release-index.json',result['public_downloads'])
        self.assertNotIn('beta-cert.pem',result['public_downloads'])
        first_wrapper=next(i for i,name in enumerate(result['public_downloads']) if name.startswith('installers/'))
        self.assertTrue(all(i<first_wrapper for i,name in enumerate(result['public_downloads']) if name.startswith('source/')))
        for profile in r.publisher.PROFILES:
            lines=(out/'setup'/profile/'default-explicit.txt').read_text().splitlines()
            self.assertEqual(lines[0],'@EXPLICIT'); self.assertEqual(len(lines),60)
            self.assertTrue(all('/label/beta/' in line and '#sha256:' in line for line in lines[1:]))
            self.assertEqual(len(list((out/'setup'/profile/'units').glob('*.txt'))),60)
            original=self.transports[profile,'maintenance'][0]/'d13-maintenance/result.json'
            self.assertEqual((out/'evidence'/profile/'native-maintenance.json').read_bytes(),original.read_bytes())
        for row in result['artifacts']:
            self.assertEqual(r.c.sha((out/row['path']).read_bytes()),row['sha256'])
    def test_complete_bundle_is_accepted_by_download_plan_schema(self):
        import beta_downloads as downloads
        result=self.assemble(); output=self.root/'release'; signatures=self.root/'signatures';signatures.mkdir()
        manifest={'release_index':{'path':'release-index.json','sha256':r.c.sha((output/'release-index.json').read_bytes())},
            'artifacts':r.signing.artifact_rows(output,[path for path in output.rglob('*') if path.is_file()])}
        (signatures/'beta-manifest.json').write_bytes(r.fs.canonical(manifest))
        (signatures/'beta-manifest.sig').write_bytes(b's'*384)
        (signatures/'beta-cert.pem').write_bytes((output/'identity/beta-cert.pem').read_bytes())
        with patch.object(downloads.signing,'verify',return_value={'release_index_sha256':manifest['release_index']['sha256']}):
            plan=downloads.prepare(output,signatures,self.certpin,'b'*64,Path('/openssl'))
        self.assertEqual(len(plan['objects']),len(result['public_downloads'])+3)
        self.assertGreater(len(result['public_downloads']),256)
        self.assertTrue(plan['objects'][0]['path'].startswith('source/'))
    def test_wrong_native_payload_lineage_refuses_before_output(self):
        profile='ubuntu26.04-amd64'; changed=copy.deepcopy(self.transports[profile,'maintenance'][1])
        changed['lineage']['payload_inventory_sha256']='0'*64
        folder,old,proof=self.transports[profile,'maintenance'];self.transports[profile,'maintenance']=(folder,changed,proof)
        with self.assertRaisesRegex(ValueError,'lineage'):self.assemble()
        self.assertFalse((self.root/'release').exists())
    def test_incomplete_owner_campaign_refuses_before_output(self):
        self.transports['ubuntu24.04-arm64','maintenance'][1]['units'][0]['interrupted_removal_resumed']=False
        with self.assertRaisesRegex(ValueError,'owner campaign'): self.assemble()
        self.assertFalse((self.root/'release').exists())
    def test_wrong_native_lineage_and_pkg_bytes_refuse(self):
        self.transports['macos15-arm64','native_pkg'][1]['pkg_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'PKG qualification'): self.assemble()
        self.assertFalse((self.root/'release').exists())
    def test_changed_selected_package_never_writes_completion_index(self):
        root=self.transports['macos15-arm64','beta'][0]; package=next((root/'carriers/channel/osx-arm64').glob('*.conda'))
        package.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'input changed'): self.assemble()
        self.assertFalse((self.root/'release/release-index.json').exists())
    def test_missing_profile_and_unselected_request_refuse(self):
        self.request['profiles'].pop('ubuntu26.04-amd64'); self.save_request()
        with self.assertRaisesRegex(ValueError,'four-profile'): self.assemble()
        self.assertFalse((self.root/'release').exists())
    def test_extra_docs_are_pinned_and_confined(self):
        doc=self.root/'guide.md'; doc.write_bytes(b'Approved beta instructions')
        self.request['additional_documents']=[{'source':str(doc),'path':'docs/INSTALL.md','sha256':r.c.sha(doc.read_bytes())}]; self.save_request()
        result=self.assemble(); self.assertIn('docs/INSTALL.md',result['public_downloads'])
    def test_beta_acceptance_maps_bound_approval_and_actual_supported_gates(self):
        result=self.assemble(); acceptance=result['beta_acceptance']
        decision=json.loads((self.root/'release/publisher-decision.json').read_bytes())
        self.assertEqual(acceptance['scope'],'initial-public-beta')
        self.assertTrue(acceptance['engineering_qualification_complete'])
        self.assertEqual(acceptance['publisher_legal_approval'],decision['legal_approval'])
        self.assertEqual(acceptance['publisher_acceptance'],decision['publisher_acceptance'])
        self.assertEqual(acceptance['publisher_decision_sha256'],r.c.sha((self.root/'release/publisher-decision.json').read_bytes()))
        self.assertFalse(decision['release_acceptance_complete'])
        self.assertFalse(acceptance['separate_reviewer_independence_claimed'])
        self.assertTrue(acceptance['historical_qualification_records_preserved'])
        self.assertEqual(acceptance['supported_gate_counts'],{'profiles':4,'native_pkg_install_and_removal_profiles':1,
            'default_carrier_packages':236,'optional_source_packages':4,'codex_cases':88,'native_owner_receipts':204,
            'carrier_packaging_revision_transactions':728,'shell_install_and_removal_profiles':4,'first_run_retention_profiles':4})
        self.assertFalse(result['publication_performed']);self.assertFalse(result['signature_performed'])
        for key in ('recognized_apple_trust_claimed','distinct_native_version_upgrade_qualified','distinct_native_version_rollback_qualified'):
            self.assertFalse(acceptance[key])
    def test_changed_publisher_acceptance_cannot_create_beta_mapping(self):
        path=Path(self.request['publisher_decision']['path']);decision=json.loads(path.read_bytes())
        decision['publisher_acceptance']=False;path.write_bytes(r.fs.canonical(decision))
        with self.assertRaisesRegex(ValueError,'input changed'):self.assemble()
        self.assertFalse((self.root/'release').exists())
    def test_source_package_independent_selection_and_false_claims_preserved(self):
        result=self.assemble()
        for profile in r.publisher.PROFILES:
            rows=[row for row in result['conda_packages'] if row['profile']==profile]
            self.assertEqual(sum(row['selection']=='default' for row in rows),59)
            self.assertEqual(sum(row['selection']=='optional-source' for row in rows),1)
        self.assertFalse(result['publication_performed']); self.assertFalse(result['signature_performed'])
        self.assertFalse(result['independent_separate_reviewer_claimed']); self.assertFalse(result['main_modified'])


if __name__=='__main__': unittest.main()
