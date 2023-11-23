import tempfile
import os

from langchain.embeddings.openai import OpenAIEmbeddings
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.document_loaders import DirectoryLoader, TextLoader
from langchain.vectorstores import Pinecone
from docx import Document as DocxDocument
from PyPDF2 import PdfReader
import pinecone

def create_indexes(files: list[str], pinecone_api_key: str, pinecone_environment: str, pinecone_index_name: str, openai_api_key: str) -> str:
    OUTPUT_DIR = os.path.join(
      tempfile.gettempdir(),
      'rkk-document-gpt',
      'output'
    )
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    try:
        text = ''
        for file_path in files:
            if file_path.endswith('.docx'):
                doc = DocxDocument(file_path)
                for para in doc.paragraphs:
                    text += para.text
            elif file_path.endswith('.pdf'):
                reader = PdfReader(file_path)
                for page in reader.pages:
                    text += page.extract_text()
            else:
                return 'Unsupported file type.'
        output_file_path = os.path.join(
            OUTPUT_DIR,
            'output.txt'
        )
        with open(output_file_path, 'w') as file:
            file.write(text)
        loader = DirectoryLoader(
            f'{OUTPUT_DIR}',
            glob='**/*.txt',
            loader_cls=TextLoader
        )
        documents = loader.load()
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1024,
            chunk_overlap=0
        )
        texts = text_splitter.split_documents(documents)
        embeddings = OpenAIEmbeddings(
            openai_api_key=openai_api_key
        )
        pinecone.init(
            api_key=pinecone_api_key,
            environment=pinecone_environment
        )
        indexes_list = pinecone.list_indexes()
        if pinecone_index_name not in indexes_list:
            pinecone.create_index(
                name=pinecone_index_name,
                dimension=1536
            )
        Pinecone.from_documents(
            documents=texts,
            embedding=embeddings,
            index_name=pinecone_index_name
        )
        os.unlink(output_file_path)
        return 'Document uploaded.'
    except Exception as e:
        return e

def clear_indexes(pinecone_api_key: str, pinecone_environment: str, pinecone_index_name: str) -> str:
    try:
        pinecone.init(
            api_key=pinecone_api_key,
            environment=pinecone_environment
        )
        indexes_list = pinecone.list_indexes()
        if pinecone_index_name in indexes_list:
            pinecone.delete_index(name=pinecone_index_name)
        return 'Index Removed', None
    except Exception as e:
        return e, None
    